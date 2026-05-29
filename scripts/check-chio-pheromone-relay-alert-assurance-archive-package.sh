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
    echo "usage: check-chio-pheromone-relay-alert-assurance-archive-package.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-pheromone-relay-alert-assurance-archive-package.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chio-pheromone/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"
ASSURANCE_DIR="$ROOT/examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance"
NOW_UNIX_MS=1766000100000
TMP_DIRS=()
cleanup() {
  if [[ ${#TMP_DIRS[@]} -gt 0 ]]; then
    rm -rf "${TMP_DIRS[@]}"
  fi
}
trap cleanup EXIT

python3 - "$SCHEMA_DIR" "$SCHEMA_REGISTRY" "$ASSURANCE_DIR" <<'PY'
import json
import pathlib
import sys

schema_dir, registry_path, fixture_dir = map(pathlib.Path, sys.argv[1:])
registry = json.loads(registry_path.read_text(encoding="utf-8"))
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
expected = {
    "chio.pheromone.relay-alert-assurance-archive-package-manifest.v1": "relay-alert-assurance-archive-package-manifest.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-package-report.v1": "relay-alert-assurance-archive-package-report.schema.json",
    "chio.pheromone.relay-alert-assurance-trusted-archive-packagers.v1": "relay-alert-assurance-trusted-archive-packagers.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-extraction-report.v1": "relay-alert-assurance-archive-extraction-report.schema.json",
    "chio.pheromone.relay-alert-assurance-physical-archive-evidence.v1": "relay-alert-assurance-physical-archive-evidence.schema.json",
    "chio.pheromone.relay-alert-assurance-physical-archive-drill-report.v1": "relay-alert-assurance-physical-archive-drill-report.schema.json",
    "chio.pheromone.relay-alert-assurance-retention-handoff-profile.v1": "relay-alert-assurance-retention-handoff-profile.schema.json",
    "chio.pheromone.relay-alert-assurance-retention-handoff-evidence.v1": "relay-alert-assurance-retention-handoff-evidence.schema.json",
    "chio.pheromone.relay-alert-assurance-retention-handoff-report.v1": "relay-alert-assurance-retention-handoff-report.schema.json",
    "chio.pheromone.relay-alert-assurance-archive-package-negative-fixture-corpus.v1": "relay-alert-assurance-archive-package-negative-fixture-corpus.schema.json",
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

negative = json.loads((fixture_dir / "relay-alert-assurance-archive-package-negative-cases.json").read_text(encoding="utf-8"))
case_ids = {case.get("caseId") for case in negative.get("cases", [])}
required = {
    "untrusted_packager",
    "path_traversal_member",
    "absolute_path_member",
    "backslash_path_member",
    "drive_colon_path_member",
    "duplicate_path_member",
    "casefold_collision_member",
    "symlink_member",
    "hardlink_member",
    "extra_member",
    "missing_member",
    "hash_mismatch_member",
    "dynamic_retention_handoff_url",
    "wrong_expected_code",
}
missing = sorted(required - case_ids)
if missing:
    raise SystemExit(f"archive package negative corpus missing cases: {missing}")
print("OK Chio relay alert assurance archive package metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/relay-alert-assurance-trusted-archive-packagers.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-handoff-profile.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-retention-handoff-profile.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-package-negative-fixture-corpus.schema.json" "$ASSURANCE_DIR/relay-alert-assurance-archive-package-negative-cases.json"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

GENERATED_DIR="$(mktemp -d)"
TMP_DIRS+=("$GENERATED_DIR")
mkdir -p "$GENERATED_DIR/export-bundle"

python3 - "$ASSURANCE_DIR/relay-alert-assurance-closeout-profile.json" "$GENERATED_DIR/package-closeout-profile.json" <<'PY'
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
profile = json.loads(source.read_text(encoding="utf-8"))
profile["blockLegalHold"] = False
target.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
PY

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance export \
  --package "$ASSURANCE_DIR/relay-alert-assurance-package.json" \
  --alert-report "$ASSURANCE_DIR/relay-alert-report.json" \
  --trend-report "$ASSURANCE_DIR/relay-trend-report.json" \
  --handoff-report "$ASSURANCE_DIR/relay-alert-handoff-report.json" \
  --normalization-report "$ASSURANCE_DIR/relay-alert-normalization-report.json" \
  --delivery-report "$ASSURANCE_DIR/relay-alert-delivery-report.json" \
  --acknowledgement-report "$ASSURANCE_DIR/relay-alert-acknowledgement-report.json" \
  --drift-report "$ASSURANCE_DIR/relay-alert-delivery-drift-report.json" \
  --review-packet "$ASSURANCE_DIR/relay-alert-route-review-packet.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --signing-key "$ASSURANCE_DIR/relay-alert-assurance-export-signing-key.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --out-dir "$GENERATED_DIR/export-bundle" \
  --report "$GENERATED_DIR/relay-alert-assurance-export-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive plan \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-profile "$ASSURANCE_DIR/relay-alert-assurance-archive-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-archive-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance closeout review \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --closeout-profile "$GENERATED_DIR/package-closeout-profile.json" \
  --retention-profile "$ASSURANCE_DIR/relay-alert-assurance-retention-profile.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package create \
  --bundle-root "$GENERATED_DIR/export-bundle" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
  --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
  --signing-key "$ASSURANCE_DIR/relay-alert-assurance-export-signing-key.json" \
  --package-id relay-alert-assurance-archive-package-001 \
  --packager-key-id default \
  --now-unix-ms "$NOW_UNIX_MS" \
  --out "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" \
  --report "$GENERATED_DIR/relay-alert-assurance-archive-package-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package verify \
  --package "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" \
  --trusted-packagers "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
  --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-archive-package-verify-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package extract \
  --package "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" \
  --trusted-packagers "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
  --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
  --out-dir "$GENERATED_DIR/extracted-package" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-archive-extraction-report.json"

validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-package-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-archive-package-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-package-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-archive-package-verify-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-archive-extraction-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-archive-extraction-report.json"

python3 - "$GENERATED_DIR" "$ASSURANCE_DIR/relay-alert-assurance-retention-handoff-profile.json" <<'PY'
import hashlib
import json
import pathlib
import sys

generated = pathlib.Path(sys.argv[1])
handoff_profile = pathlib.Path(sys.argv[2])

def canonical_hash(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest(), value

package_report_hash, package_report = canonical_hash(generated / "relay-alert-assurance-archive-package-report.json")
physical = {
    "schema": "chio.pheromone.relay-alert-assurance-physical-archive-evidence.v1",
    "localKernelId": package_report["localKernelId"],
    "evidenceId": "physical-archive-evidence-001",
    "packageId": package_report["packageId"],
    "packageReportSha256": package_report_hash,
    "packageManifestSha256": package_report["packageManifestSha256"],
    "observedAtUnixMs": 1766000100000,
    "sampledMemberCount": max(1, package_report["packageMemberCount"]),
    "mediaAlias": "operator_vault_a",
    "claims": ["operator_readback_sampled"]
}
(generated / "relay-alert-assurance-physical-archive-evidence.json").write_text(json.dumps(physical, indent=2) + "\n", encoding="utf-8")
handoff = {
    "schema": "chio.pheromone.relay-alert-assurance-retention-handoff-evidence.v1",
    "localKernelId": package_report["localKernelId"],
    "evidenceId": "retention-handoff-evidence-001",
    "packageId": package_report["packageId"],
    "packageReportSha256": package_report_hash,
    "targetSystemAlias": json.loads(handoff_profile.read_text(encoding="utf-8"))["allowedSystemAliases"][0],
    "observedAtUnixMs": 1766000100000,
    "claims": ["ready_for_operator_managed_handoff"]
}
(generated / "relay-alert-assurance-retention-handoff-evidence.json").write_text(json.dumps(handoff, indent=2) + "\n", encoding="utf-8")

archive = json.loads((generated / "relay-alert-assurance-archive-report.json").read_text(encoding="utf-8"))
closeout = json.loads((generated / "relay-alert-assurance-closeout-report.json").read_text(encoding="utf-8"))
package_verify = json.loads((generated / "relay-alert-assurance-archive-package-verify-report.json").read_text(encoding="utf-8"))
extraction = json.loads((generated / "relay-alert-assurance-archive-extraction-report.json").read_text(encoding="utf-8"))
if archive.get("accepted") is not True:
    raise SystemExit("archive report must be accepted")
if closeout.get("accepted") is not True:
    raise SystemExit("package closeout report must be accepted")
# A verified report omits the boolean (skip_serializing_if = "is_true"); only a
# present-and-false value signals a nested-exporter verification failure.
if package_verify.get("accepted") is not True or package_verify.get("nestedExporterVerified", True) is not True:
    raise SystemExit("package verify report must verify nested exporters")
if extraction.get("accepted") is not True:
    raise SystemExit("archive extraction report must be accepted")
print("OK generated relay alert assurance archive package")
PY

validate_schema "$SCHEMA_DIR/relay-alert-assurance-physical-archive-evidence.schema.json" "$GENERATED_DIR/relay-alert-assurance-physical-archive-evidence.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-handoff-evidence.schema.json" "$GENERATED_DIR/relay-alert-assurance-retention-handoff-evidence.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive physical-drill review \
  --evidence "$GENERATED_DIR/relay-alert-assurance-physical-archive-evidence.json" \
  --package-report "$GENERATED_DIR/relay-alert-assurance-archive-package-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-physical-archive-drill-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-physical-archive-drill-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-physical-archive-drill-report.json"

cargo run -p chio-cli --bin chio -- pheromone relay alert assurance retention handoff review \
  --evidence "$GENERATED_DIR/relay-alert-assurance-retention-handoff-evidence.json" \
  --profile "$ASSURANCE_DIR/relay-alert-assurance-retention-handoff-profile.json" \
  --package-report "$GENERATED_DIR/relay-alert-assurance-archive-package-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$GENERATED_DIR/relay-alert-assurance-retention-handoff-report.json"
validate_schema "$SCHEMA_DIR/relay-alert-assurance-retention-handoff-report.schema.json" "$GENERATED_DIR/relay-alert-assurance-retention-handoff-report.json"

cargo test -p chio-pheromone-relay alert_assurance_archive_package --test relay
cargo test -p chio-pheromone-relay physical_drill --test relay
cargo test -p chio-cli --bin chio chio_pheromone_relay_alert_assurance

NEGATIVE_DIR="$(mktemp -d)"
TMP_DIRS+=("$NEGATIVE_DIR")
python3 - "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json" "$NEGATIVE_DIR/untrusted-packagers.json" <<'PY'
import json
import pathlib
import sys

trusted_path, untrusted_path = map(pathlib.Path, sys.argv[1:])
trusted = json.loads(trusted_path.read_text(encoding="utf-8"))
trusted["packagers"][0]["publicKey"] = "0" * 64
untrusted_path.write_text(json.dumps(trusted, indent=2) + "\n", encoding="utf-8")
PY

set +e
cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package verify \
  --package "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" \
  --trusted-packagers "$NEGATIVE_DIR/untrusted-packagers.json" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
  --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/untrusted-package-report.json" >"$NEGATIVE_DIR/untrusted.out" 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -q "signature_invalid" "$NEGATIVE_DIR/untrusted.out"; then
  echo "untrusted packager negative did not fail with signature_invalid" >&2
  cat "$NEGATIVE_DIR/untrusted.out" >&2
  exit 1
fi

python3 - "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" "$NEGATIVE_DIR/traversal.tar.gz" <<'PY'
import gzip
import pathlib
import tarfile
import sys
import io

source, target = map(pathlib.Path, sys.argv[1:])
with tarfile.open(source, "r:gz") as package:
    manifest = package.extractfile("archive-package-manifest.json").read()
with tarfile.open(target, "w:gz") as package:
    info = tarfile.TarInfo("archive-package-manifest.json")
    info.size = len(manifest)
    package.addfile(info, io.BytesIO(manifest))
    payload = b"escape"
    info = tarfile.TarInfo("../escape.json")
    info.size = len(payload)
    package.addfile(info, io.BytesIO(payload))
PY

set +e
cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package verify \
  --package "$NEGATIVE_DIR/traversal.tar.gz" \
  --trusted-packagers "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json" \
  --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
  --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
  --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/traversal-report.json" >"$NEGATIVE_DIR/traversal.out" 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -Eq "not portable|unsafe" "$NEGATIVE_DIR/traversal.out"; then
  echo "path traversal negative did not fail closed" >&2
  cat "$NEGATIVE_DIR/traversal.out" >&2
  exit 1
fi

python3 - "$GENERATED_DIR/relay-alert-assurance-archive-package.tar.gz" "$NEGATIVE_DIR" <<'PY'
import io
import pathlib
import tarfile
import sys

source = pathlib.Path(sys.argv[1])
target_dir = pathlib.Path(sys.argv[2])
with tarfile.open(source, "r:gz") as package:
    entries = []
    for member in package.getmembers():
        if not member.isfile():
            continue
        extracted = package.extractfile(member)
        if extracted is None:
            continue
        entries.append((member.name, extracted.read()))

manifest = next(data for name, data in entries if name == "archive-package-manifest.json")
first_member_name, _ = next((name, data) for name, data in entries if name != "archive-package-manifest.json")

def regular(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, io.BytesIO(data)

def write_regular_archive(name, members):
    with tarfile.open(target_dir / f"{name}.tar.gz", "w:gz") as package:
        for path, data in members:
            info, body = regular(path, data)
            package.addfile(info, body)

def write_link_archive(name, link_type):
    with tarfile.open(target_dir / f"{name}.tar.gz", "w:gz") as package:
        info, body = regular("archive-package-manifest.json", manifest)
        package.addfile(info, body)
        link = tarfile.TarInfo(f"{name}.json")
        link.type = link_type
        link.linkname = "../escape.json"
        package.addfile(link)

write_regular_archive("absolute_path_member", [("archive-package-manifest.json", manifest), ("/abs.json", b"abs")])
write_regular_archive("backslash_path_member", [("archive-package-manifest.json", manifest), ("bad\\path.json", b"slash")])
write_regular_archive("drive_colon_path_member", [("archive-package-manifest.json", manifest), ("C:bad.json", b"colon")])
write_regular_archive("duplicate_path_member", [("archive-package-manifest.json", manifest), ("dup.json", b"one"), ("dup.json", b"two")])
write_regular_archive("casefold_collision_member", [("archive-package-manifest.json", manifest), ("Case.json", b"one"), ("case.json", b"two")])
write_link_archive("symlink_member", tarfile.SYMTYPE)
write_link_archive("hardlink_member", tarfile.LNKTYPE)
write_regular_archive("extra_member", entries + [("extra-member.json", b"extra")])
write_regular_archive("missing_member", [(name, data) for name, data in entries if name != first_member_name])
write_regular_archive("hash_mismatch_member", [(name, b"tampered" if name == first_member_name else data) for name, data in entries])
PY

while IFS='|' read -r case_id expected_code expected_pattern; do
  set +e
  cargo run -p chio-cli --bin chio -- pheromone relay alert assurance archive package verify \
    --package "$NEGATIVE_DIR/$case_id.tar.gz" \
    --trusted-packagers "$ASSURANCE_DIR/relay-alert-assurance-trusted-archive-packagers.json" \
    --trusted-exporters "$ASSURANCE_DIR/relay-alert-assurance-trusted-exporters.json" \
    --archive-report "$GENERATED_DIR/relay-alert-assurance-archive-report.json" \
    --closeout-report "$GENERATED_DIR/relay-alert-assurance-closeout-report.json" \
    --now-unix-ms "$NOW_UNIX_MS" \
    --report "$NEGATIVE_DIR/$case_id-report.json" >"$NEGATIVE_DIR/$case_id.out" 2>&1
  status=$?
  set -e
  if [[ "$status" -eq 0 ]] || ! grep -Eq "$expected_pattern" "$NEGATIVE_DIR/$case_id.out"; then
    echo "$case_id negative did not fail with $expected_code" >&2
    cat "$NEGATIVE_DIR/$case_id.out" >&2
    exit 1
  fi
done <<'CASES'
absolute_path_member|archive_package_invalid|archive_package_invalid|not portable|unsafe
backslash_path_member|archive_package_invalid|archive_package_invalid|not portable|unsafe
drive_colon_path_member|archive_package_invalid|archive_package_invalid|not portable|unsafe
duplicate_path_member|archive_package_invalid|archive_package_invalid|duplicate
casefold_collision_member|archive_package_invalid|archive_package_invalid|casefold
symlink_member|archive_package_invalid|archive_package_invalid|non-regular
hardlink_member|archive_package_invalid|archive_package_invalid|non-regular
extra_member|archive_package_invalid|archive_package_invalid|not listed
missing_member|body_hash_mismatch|body_hash_mismatch|file is missing
hash_mismatch_member|body_hash_mismatch|body_hash_mismatch|mismatch
CASES

python3 - "$GENERATED_DIR/relay-alert-assurance-retention-handoff-evidence.json" "$NEGATIVE_DIR/bad-handoff-evidence.json" <<'PY'
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
evidence = json.loads(source.read_text(encoding="utf-8"))
evidence["targetSystemAlias"] = "https://records.example/upload"
target.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
PY

set +e
cargo run -p chio-cli --bin chio -- pheromone relay alert assurance retention handoff review \
  --evidence "$NEGATIVE_DIR/bad-handoff-evidence.json" \
  --profile "$ASSURANCE_DIR/relay-alert-assurance-retention-handoff-profile.json" \
  --package-report "$GENERATED_DIR/relay-alert-assurance-archive-package-report.json" \
  --now-unix-ms "$NOW_UNIX_MS" \
  --report "$NEGATIVE_DIR/bad-handoff-report.json" >"$NEGATIVE_DIR/bad-handoff.out" 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -q "archive_package_invalid" "$NEGATIVE_DIR/bad-handoff.out"; then
  echo "dynamic retention handoff URL negative did not fail with archive_package_invalid" >&2
  cat "$NEGATIVE_DIR/bad-handoff.out" >&2
  exit 1
fi

python3 - "$ASSURANCE_DIR/relay-alert-assurance-archive-package-negative-cases.json" <<'PY'
import json
import pathlib
import sys

negative = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {case["caseId"]: case["expectedCode"] for case in negative["cases"]}
actual = {
    "untrusted_packager": "signature_invalid",
    "path_traversal_member": "archive_package_invalid",
    "absolute_path_member": "archive_package_invalid",
    "backslash_path_member": "archive_package_invalid",
    "drive_colon_path_member": "archive_package_invalid",
    "duplicate_path_member": "archive_package_invalid",
    "casefold_collision_member": "archive_package_invalid",
    "symlink_member": "archive_package_invalid",
    "hardlink_member": "archive_package_invalid",
    "extra_member": "archive_package_invalid",
    "missing_member": "body_hash_mismatch",
    "hash_mismatch_member": "body_hash_mismatch",
    "dynamic_retention_handoff_url": "archive_package_invalid",
}
for case_id, code in actual.items():
    if expected.get(case_id) != code:
        raise SystemExit(f"{case_id} expected {expected.get(case_id)}, actual {code}")
if expected.get("wrong_expected_code") == actual["path_traversal_member"]:
    raise SystemExit("wrong expected code detector did not trip")
print("OK relay alert assurance archive package negative cases")
PY

if [[ "$MODE" == "negative-only" ]]; then
  exit 0
fi

bash "$ROOT/scripts/check-chio-pheromone-relay-alert-assurance-archive.sh" --schema-only
