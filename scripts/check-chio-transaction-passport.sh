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
  *)
    echo "usage: check-chio-transaction-passport.sh [--schema-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-transaction-passport.sh [--schema-only]" >&2
  exit 2
fi

CATALOG="$ROOT/fixtures/proof-room/catalog.json"
REGISTRY="$ROOT/spec/schemas/registry.json"
SCHEMA_ID="chio.transaction-passport.v1"
SCHEMA_FILE="spec/schemas/chio-transaction/v1/transaction-passport.schema.json"

python3 - "$ROOT" "$REGISTRY" "$CATALOG" "$SCHEMA_ID" "$SCHEMA_FILE" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
registry_path = pathlib.Path(sys.argv[2])
catalog_path = pathlib.Path(sys.argv[3])
schema_id = sys.argv[4]
schema_file = sys.argv[5]

registry = json.loads(registry_path.read_text(encoding="utf-8"))
rows = [
    row
    for row in registry.get("artifacts", [])
    if row.get("schema") == schema_id and row.get("schemaFile") == schema_file
]
if len(rows) != 1:
    raise SystemExit(
        f"transaction-passport schema must have exactly one registry row for {schema_file}"
    )
if not (root / schema_file).is_file():
    raise SystemExit(f"transaction-passport schema file is missing: {schema_file}")

signed_artifact = (
    root / "crates/core/chio-core-types/src/signed_artifact.rs"
).read_text(encoding="utf-8")
if 'CHIO_TRANSACTION_PASSPORT_V1_SCHEMA: &str = "chio.transaction-passport.v1"' not in signed_artifact:
    raise SystemExit("transaction-passport schema is not named by chio-core-types")
if '"transaction_passport", "transaction-passport-v1"' not in signed_artifact:
    raise SystemExit("transaction-passport schema is not reachable from the built-in signed artifact registry")

catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
positive = []
negative = []
proof_room = []
for entry in catalog.get("fixtures", []):
    kind = entry.get("kind")
    if kind not in {"transaction-passport", "negative-transaction-passport", "proof-room"}:
        continue
    fixture_id = entry.get("id")
    fixture_path = entry.get("path")
    if not fixture_id or not fixture_path:
        raise SystemExit(f"transaction-passport catalog entry is missing id/path: {entry}")
    if kind == "proof-room":
        bundle_path = root / fixture_path / "proof-room-bundle"
        manifest_path = bundle_path / "manifest.json"
        passport_path = bundle_path / "roots" / "transaction-passport.json"
        if not manifest_path.is_file():
            raise SystemExit(f"Proof Room fixture manifest is missing: {manifest_path.relative_to(root)}")
        if not passport_path.is_file():
            raise SystemExit(f"Proof Room fixture passport is missing: {passport_path.relative_to(root)}")
        proof_room.append(fixture_id)
    elif kind == "transaction-passport":
        passport_path = root / fixture_path / "transaction-passport.json"
        if not passport_path.is_file():
            raise SystemExit(f"transaction-passport fixture is missing: {passport_path.relative_to(root)}")
        positive.append(fixture_id)
    else:
        passport_path = root / fixture_path / "transaction-passport.json"
        if not passport_path.is_file():
            raise SystemExit(f"transaction-passport fixture is missing: {passport_path.relative_to(root)}")
        negative.append(fixture_id)

if not positive:
    raise SystemExit("transaction-passport catalog has no positive fixtures")
if not negative:
    raise SystemExit("transaction-passport catalog has no negative fixtures")
if not proof_room:
    raise SystemExit("transaction-passport catalog has no Proof Room fixtures")

print(
    f"OK transaction-passport schema and catalog metadata: "
    f"{len(positive)} positive, {len(negative)} negative, {len(proof_room)} proof-room"
)
PY

cargo test -p chio-core-types --test signed_artifact_schema known_signed_artifact_schemas -- --nocapture

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ -n "${CHIO_BIN:-}" ]]; then
  if [[ ! -x "$CHIO_BIN" ]]; then
    echo "CHIO_BIN is not executable: $CHIO_BIN" >&2
    exit 2
  fi
elif [[ -x "$target_dir/debug/chio" ]]; then
  CHIO_BIN="$target_dir/debug/chio"
else
  cargo build -p chio-cli --bin chio
  CHIO_BIN="$target_dir/debug/chio"
fi
unset target_dir

# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$ROOT/scripts/lib/chio-proof-trusted-keys.sh"
PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON='{"chain_id":"eip155:8453","observed_block_number":12345678,"observed_block_hash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","latest_block_number":12345701}'

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

verify_positive() {
  local fixture_id="$1"
  local passport_path="$2"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"

  if ! "$CHIO_BIN" proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"; then
    echo "transaction-passport positive fixture failed: $fixture_id" >&2
    cat "$stderr_path" >&2
    cat "$stdout_path" >&2
    return 1
  fi
  python3 - "$stdout_path" "$fixture_id" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture_id = sys.argv[2]
if report.get("verdict") != "verified":
    raise SystemExit(f"positive fixture {fixture_id} did not verify: {report.get('verdict')}")
PY
}

verify_negative() {
  local fixture_id="$1"
  local passport_path="$2"
  local metadata_path="${3:-}"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"
  local verifier_context

  verifier_context="$(negative_verifier_context "$metadata_path")"

  if run_negative_verify "$verifier_context" "$passport_path" "$stdout_path" "$stderr_path"; then
    echo "transaction-passport negative fixture unexpectedly verified: $fixture_id" >&2
    cat "$stdout_path" >&2
    return 1
  fi
}

negative_verifier_context() {
  local metadata_path="${1:-}"
  if [[ -z "$metadata_path" || ! -f "$metadata_path" ]]; then
    printf 'none\n'
    return 0
  fi
  python3 - "$metadata_path" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
context = metadata.get("verifier_context") or {}
print(context.get("public_settlement_independent_chain_head") or "none")
PY
}

run_negative_verify() {
  local verifier_context="$1"
  local passport_path="$2"
  local stdout_path="$3"
  local stderr_path="$4"

  case "$verifier_context" in
    missing)
      env -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON \
        -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL \
        "$CHIO_BIN" proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    block_hash_mismatch)
      env \
        CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON="$PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON" \
        -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL \
        "$CHIO_BIN" proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    none)
      "$CHIO_BIN" proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    *)
      echo "unknown negative verifier context: $verifier_context" >&2
      return 2
      ;;
  esac
}

verify_proof_room() {
  local fixture_id="$1"
  local bundle_path="$2"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"

  if ! "$CHIO_BIN" proof verify "$bundle_path" >"$stdout_path" 2>"$stderr_path"; then
    echo "Proof Room fixture failed: $fixture_id" >&2
    cat "$stderr_path" >&2
    cat "$stdout_path" >&2
    return 1
  fi
  python3 - "$stdout_path" "$fixture_id" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture_id = sys.argv[2]
if report.get("verdict") != "verified":
    raise SystemExit(f"Proof Room fixture {fixture_id} did not verify: {report.get('verdict')}")
PY
}

positive_count=0
negative_count=0
proof_room_count=0
fixture_rows="$tmpdir/transaction-passport-fixtures.tsv"
python3 - "$ROOT" "$CATALOG" >"$fixture_rows" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
catalog = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
for entry in catalog.get("fixtures", []):
    kind = entry.get("kind")
    if kind not in {"transaction-passport", "negative-transaction-passport", "proof-room"}:
        continue
    fixture_id = entry["id"]
    if kind == "proof-room":
        rel = pathlib.Path(entry["path"]) / "proof-room-bundle"
        metadata = ""
        if not (root / rel / "manifest.json").is_file():
            raise SystemExit(f"missing Proof Room fixture manifest: {rel / 'manifest.json'}")
    else:
        base = pathlib.Path(entry["path"])
        rel = base / "transaction-passport.json"
        metadata_path = base.parent / "negatives" / f"{base.name}.json"
        metadata = str(metadata_path) if (root / metadata_path).is_file() else ""
        if not (root / rel).is_file():
            raise SystemExit(f"missing fixture passport: {rel}")
    print(f"{kind}\t{fixture_id}\t{rel}\t{metadata}")
PY

while IFS=$'\t' read -r kind fixture_id fixture_path metadata_path; do
  case "$kind" in
    transaction-passport)
      verify_positive "$fixture_id" "$ROOT/$fixture_path"
      positive_count=$((positive_count + 1))
      ;;
    negative-transaction-passport)
      verify_negative "$fixture_id" "$ROOT/$fixture_path" "${metadata_path:+$ROOT/$metadata_path}"
      negative_count=$((negative_count + 1))
      ;;
    proof-room)
      verify_proof_room "$fixture_id" "$ROOT/$fixture_path"
      proof_room_count=$((proof_room_count + 1))
      ;;
    *)
      echo "unexpected proof fixture kind: $kind" >&2
      exit 1
      ;;
  esac
done <"$fixture_rows"

printf 'OK transaction-passport verifier gate: %s positive, %s negative, %s proof-room\n' \
  "$positive_count" "$negative_count" "$proof_room_count"
