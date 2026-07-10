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

if [[ -n "${CHIO_BIN:-}" ]]; then
  if [[ ! -x "$CHIO_BIN" ]]; then
    echo "CHIO_BIN is not executable: $CHIO_BIN" >&2
    exit 2
  fi
elif [[ -x "$ROOT/target/debug/chio" ]]; then
  CHIO_BIN="$ROOT/target/debug/chio"
else
  cargo build -p chio-cli --bin chio
  CHIO_BIN="$ROOT/target/debug/chio"
fi

export CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET="${CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET:-chio-agent-web-standard-webhooks-fixture-secret-v1}"
export CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS="${CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS:-1770508860}"
export CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS="${CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS:-300}"
export CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS="${CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS:-43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737,fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565}"
export CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS="${CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS:-d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737}"
export CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS="${CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS:-31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869}"
export CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS="${CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a}"
export CHIO_TRANSACTION_TRUSTED_ROOT_KEYS="${CHIO_TRANSACTION_TRUSTED_ROOT_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a}"
export CHIO_RUNTIME_TRUSTED_ROOT_KEYS="${CHIO_RUNTIME_TRUSTED_ROOT_KEYS:-5b8649c0cfcdbe78a5ff962edfa48914dfd45af22afe358de1f4dd7e4567d5ca}"
export CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS="${CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS:-f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d}"
export CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS="${CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS:-3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2}"
export CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS="${CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS:-31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869}"
export CHIO_SWARM_TRUSTED_WITNESS_KEYS="${CHIO_SWARM_TRUSTED_WITNESS_KEYS:-43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de}"
export CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS="${CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS:-e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa}"
export CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS="${CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS:-e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa}"
export CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS="${CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS:-cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7}"
export CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS="${CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS:-1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca}"
export CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS="${CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c}"
export CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS="${CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS:-fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS:-fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS:-91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS:-d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID:-chio.official-web3-contracts}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH:-0x454a9a92b54a835a2776750196b171501bff6e5c02df1a192616194fc0a095cc}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH:-0xfc5d76d87b02096c6ae32ce644a2b98ca0bdf3c56700ad16731fad2062e6bd7f}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH:-0xd4f87cc63c00d0640c8f232c8fac5e5cb99bc6cf185ef912225e07fa438614cc}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH:-0x03d8f545c330922a33db6473430c50eafd527e04474f31abee2dc1f8c6ab2d36}"
export CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH:-0x17f7936469584b38404765ac44bd7e2384337983e4bc6448a3500d0637711f09}"
export CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS="${CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS:-eip155:8453,eip155:42161}"
export CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS="${CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS:-1}"
export CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON="${CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON:-{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}}"
export CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS="${CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS:-1743293560}"
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
