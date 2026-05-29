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
    echo "usage: check-chio-pheromone-runtime.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-runtime.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
SCHEMA_MANIFEST="$ROOT/spec/schemas/MANIFEST.sha256"
FIXTURE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone"
PACKAGE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
CONTEXT_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verification-context.json"

python3 - "$ROOT" "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$SCHEMA_MANIFEST" "$FIXTURE_DIR" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

root, schema_dir, registry_path, manifest_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
gate_paths = [
    root / "scripts/check-chio-authority-issuance.sh",
    root / "scripts/check-chio-pheromone-runtime.sh",
    root / "scripts/check-chio-pheromone-transit.sh",
]
legacy_markers = [
    "generate-" + "chio" + "dos-proof-package",
    "/tmp/" + "chio" + "dos-pheromone",
]
for path in gate_paths:
    text = path.read_text(encoding="utf-8")
    for marker in legacy_markers:
        if marker in text:
            rel = path.relative_to(root)
            raise SystemExit(f"active Chio gate {rel} uses legacy marker {marker}")
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
registered_paths = {entry.get("schemaFile") for entry in registry.get("artifacts", [])}
for entry in registry.get("artifacts", []):
    schema_file = entry.get("schemaFile", "")
    if schema_file.startswith("spec/schemas/chio/"):
        raise SystemExit(f"Chio registry still points at retired schema root {schema_file}")
manifest = {}
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    digest, path = line.split(None, 1)
    manifest[path] = digest
for schema_path in sorted(schema_dir.glob("*.schema.json")) + sorted((root / "spec/schemas/chio-runtime/v1").glob("*.schema.json")):
    rel = str(schema_path.relative_to(root))
    if rel not in registered_paths:
        raise SystemExit(f"Chio schema {rel} is not registered in registry.json")
    if rel not in manifest:
        raise SystemExit(f"Chio schema {rel} is absent from MANIFEST.sha256")
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode != 0:
        raise SystemExit(f"Chio schema {rel} exists but is not tracked by git")
expected = {
    "chio.pheromone-deposit.v1": "spec/schemas/chio-pheromone/v1/deposit.schema.json",
    "chio.pheromone-cost-commitment.v1": "spec/schemas/chio-pheromone/v1/cost-commitment.schema.json",
    "chio.pheromone-observation-cost-statement.v1": "spec/schemas/chio-pheromone/v1/observation-cost-statement.schema.json",
    "chio.pheromone-observation-cost-telemetry-root.v1": "spec/schemas/chio-pheromone/v1/observation-cost-telemetry-root.schema.json",
    "chio.pheromone-observation-cost-leaf.v1": "spec/schemas/chio-pheromone/v1/observation-cost-leaf.schema.json",
    "chio.pheromone-observation-cost-verifier-root.v1": "spec/schemas/chio-pheromone/v1/observation-cost-verifier-root.schema.json",
    "chio.runtime.trust-floor-state.v1": "spec/schemas/chio-runtime/v1/trust-floor-state.schema.json",
    "chio.pheromone-scarcity-policy.v1": "spec/schemas/chio-pheromone/v1/scarcity-policy.schema.json",
    "chio.pheromone-scarcity-window-id.v1": "spec/schemas/chio-pheromone/v1/scarcity-window-id.schema.json",
    "chio.pheromone.receive-report.v1": "spec/schemas/chio-pheromone/v1/receive-report.schema.json",
    "chio.pheromone.query-report.v1": "spec/schemas/chio-pheromone/v1/query-report.schema.json",
    "chio.pheromone.peer-weights.v1": "spec/schemas/chio-pheromone/v1/peer-weights.schema.json",
}
for schema_id, want in expected.items():
    path = root / want
    if not path.is_file():
        raise SystemExit(f"missing schema {want}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or "$id" not in schema:
        raise SystemExit(f"schema {want} is not a frozen object schema")
    if registered.get(schema_id) != want:
        raise SystemExit(f"schema {schema_id} is not registered at {want}")
    if want not in manifest:
        raise SystemExit(f"schema {schema_id} is absent from MANIFEST.sha256")
    actual = hashlib.sha256((root / want).read_bytes()).hexdigest()
    if manifest[want] != actual:
        raise SystemExit(f"schema {schema_id} manifest hash is stale")
    schema_text = (root / want).read_text(encoding="utf-8")
    retired_schema_prefix = "chio." + "chio."
    if retired_schema_prefix in schema_text:
        raise SystemExit(f"schema {schema_id} allows legacy Chio schema ids")
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", want],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode != 0:
        raise SystemExit(f"schema {schema_id} exists but is not tracked by git")

policy_envelope = json.loads((fixture_dir / "transit-policy.json").read_text(encoding="utf-8"))
policy = policy_envelope.get("body", {})
receive = json.loads((fixture_dir / "receive-report.json").read_text(encoding="utf-8"))
query = json.loads((fixture_dir / "query-report.json").read_text(encoding="utf-8"))
weights = json.loads((fixture_dir / "peer-weights.json").read_text(encoding="utf-8"))

if "body" not in policy_envelope or "signerKey" not in policy_envelope or "signature" not in policy_envelope:
    raise SystemExit("runtime policy must be a signed envelope")
admission = policy.get("admission", {})
if admission.get("recipientKernelId") != "did:chio:dataco":
    raise SystemExit("runtime policy recipient is not verifier-owned")
if admission.get("authenticatedSenderKernelId") != "did:chio:buyer-kernel":
    raise SystemExit("runtime policy authenticated sender is not verifier-owned")
if not admission.get("passports"):
    raise SystemExit("runtime policy must carry admitted passport material")
scarcity = admission.get("scarcityPolicies", [])
if len(scarcity) != 1:
    raise SystemExit("runtime policy must carry explicit scarcity policy material")
if scarcity[0].get("schema") != "chio.pheromone-scarcity-policy.v1":
    raise SystemExit("runtime scarcity policy schema mismatch")
if scarcity[0].get("newcomerHorizonEpochs") != 8:
    raise SystemExit("runtime scarcity policy default horizon is not explicit")
for field in ("runtimePolicySha256", "policySha256"):
    value = scarcity[0].get(field, "")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise SystemExit(f"runtime scarcity policy missing canonical {field}")
if scarcity[0].get("activePeersEpoch") != scarcity[0].get("reputationEpoch"):
    raise SystemExit("runtime scarcity policy active peer epoch must be explicit")
if receive.get("schema") != "chio.pheromone.receive-report.v1" or not receive.get("accepted"):
    raise SystemExit("committed receive report must be accepted")
if receive.get("batchOutcome") != "accepted":
    raise SystemExit("committed receive report must carry accepted batch outcome")
if receive.get("acceptedFrameCount") != 1 or receive.get("rejectedFrameCount") != 0:
    raise SystemExit("committed receive report must carry frame outcome counts")
if query.get("schema") != "chio.pheromone.query-report.v1" or not query.get("accepted"):
    raise SystemExit("committed query report must be accepted")
if weights.get("schema") != "chio.pheromone.peer-weights.v1":
    raise SystemExit("peer weights fixture has wrong schema")
print("OK Chio pheromone runtime metadata")
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
validate_schema "$ROOT/spec/schemas/chio-runtime/v1/trust-floor-state.schema.json" <(printf '%s\n' '{
  "schema": "chio.runtime.trust-floor-state.v1",
  "entries": [
    {
      "verifierId": "did:chio:buyer-verifier",
      "keyId": "verifier-key-1",
      "highestVersion": 1,
      "latestBundleSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "latestRevocationCheckpointSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ]
}')

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

if [[ "$MODE" == "negative-only" ]]; then
  cargo test -p chio-pheromone-runtime --test runtime_receiver runtime_policy_loader_rejects -- --nocapture
  cargo test -p chio-pheromone-runtime --test runtime_receiver storage_commit_failure_is_reported_without_accepting_frame -- --nocapture
  cargo test -p chio-pheromone-runtime --test runtime_receiver sqlite_receive_rolls_back_accepted_state_when_report_persistence_fails -- --nocapture
  cargo test -p chio-pheromone --test pheromone_substrate observation_cost_commitment_rejects_untrusted_invalid_and_revoked_roots -- --nocapture
  exit 0
fi

cargo test -p chio-pheromone-runtime
cargo test -p chio-cli --bin chio chio_pheromone

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures -- \
  --pheromone-out-dir "$tmpdir/pheromone"

for filename in deposit.json gossip-batch.json transit-policy.json concentration.json negative-cases.json receive-report.json query-report.json peer-weights.json; do
  cmp "$FIXTURE_DIR/$filename" "$tmpdir/pheromone/$filename"
done

run_receive() {
  cargo run -p chio-cli --bin chio -- pheromone receive \
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
if report.get("batchOutcome") != "accepted":
    raise SystemExit("CLI receive report did not carry accepted batch outcome")
if report.get("acceptedFrameCount") != 1 or report.get("rejectedFrameCount") != 0:
    raise SystemExit("CLI receive report did not carry frame outcome counts")
PY

cargo run -p chio-cli --bin chio -- pheromone query \
  --store "$store" \
  --subject-class support.prompt_injection \
  --namespace dev.chio.support \
  --reputation-epoch 42 \
  --peer-weights "$FIXTURE_DIR/peer-weights.json" \
  --report "$tmpdir/query-report.json"
python3 - "$tmpdir/query-report.json" "$FIXTURE_DIR/transit-policy.json" "$FIXTURE_DIR/peer-weights.json" "$store" <<'PY'
import json
import sqlite3
import sys
report = json.loads(open(sys.argv[1], encoding="utf-8").read())
policy = json.loads(open(sys.argv[2], encoding="utf-8").read()).get("body", {})
weights = json.loads(open(sys.argv[3], encoding="utf-8").read())
store = sys.argv[4]
if not report.get("accepted"):
    raise SystemExit("CLI query did not accept the stored fixture")
concentration = report.get("concentration", {})
total = concentration.get("total_strength")
unweighted = concentration.get("unweighted_total_strength")
if not isinstance(total, (int, float)) or not isinstance(unweighted, (int, float)):
    raise SystemExit("CLI query report does not carry usable concentration strength")
with sqlite3.connect(store) as conn:
    persisted = conn.execute(
        "SELECT COUNT(*) FROM chio_pheromone_passport_admissions"
    ).fetchone()[0]
if persisted < 1:
    raise SystemExit("CLI receive did not persist passport admission history")
if unweighted > 0:
    passport = policy["admission"]["passports"][0]
    epoch = weights["reputationEpoch"]
    first_seen = passport["firstSeenEpoch"]
    scarcity = policy["admission"].get("scarcityPolicies", [])
    horizon = scarcity[0].get("newcomerHorizonEpochs", 8) if scarcity else 8
    discount = min((epoch - first_seen + 1) / horizon, 1.0)
    weight = weights["weights"][0]["weight"]
    expected_ratio = weight * discount
    actual_ratio = total / unweighted
    if abs(actual_ratio - expected_ratio) > 0.000001:
        raise SystemExit(
            f"CLI query ratio {actual_ratio} did not use persisted passport history {expected_ratio}"
        )
PY

set +e
run_receive "$FIXTURE_DIR/gossip-batch.json" "$store" "$tmpdir/replay-report.json" >/tmp/chio-pheromone-replay.out 2>/tmp/chio-pheromone-replay.err
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
run_receive "$tmpdir/wrong-recipient-batch.json" "$tmpdir/wrong-recipient.sqlite3" "$tmpdir/wrong-recipient-report.json" >/tmp/chio-pheromone-recipient.out 2>/tmp/chio-pheromone-recipient.err
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

bash "$ROOT/scripts/check-chio-pheromone-transit.sh"
