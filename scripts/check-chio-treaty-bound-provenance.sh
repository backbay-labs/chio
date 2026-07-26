#!/usr/bin/env bash
set -euo pipefail

MODE="full"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    ;;
  "--negative-only")
    MODE="negative-only"
    ;;
  *)
    echo "usage: check-chio-treaty-bound-provenance.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chio-treaty-bound-provenance.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
federation_schema_dir="$repo_root/spec/schemas/chio-federation/v1"
attest_schema_dir="$repo_root/spec/schemas/chio-attest/v1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

validate_schema() {
  cargo run -p chio-spec-validate -- "$1" "$2" >/dev/null
}

canonical_hash() {
  python3 - "$1" <<'PY'
import hashlib
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)
payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
print(hashlib.sha256(payload).hexdigest())
PY
}

rebind_lineage_and_bilateral() {
  python3 - "$tmpdir/lineage.json" "$tmpdir/bilateral.json" "$tmpdir/lineage-asserted.json" <<'PY'
import hashlib
import json
import sys


def canonical_hash(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


lineage_path, bilateral_path, asserted_path = sys.argv[1:4]
with open(lineage_path, "r", encoding="utf-8") as handle:
    lineage = json.load(handle)
with open(bilateral_path, "r", encoding="utf-8") as handle:
    bilateral = json.load(handle)

binding_payload = {
    "schema": bilateral["schema"],
    "invocationId": bilateral["invocationId"],
    "treatyId": bilateral["treatyId"],
    "ladderIntersectionSha256": bilateral["ladderIntersectionSha256"],
    "continuationSha256": bilateral["continuationSha256"],
    "actionClassId": bilateral["actionClassId"],
    "consistencyModel": bilateral["consistencyModel"],
    "capabilityId": bilateral["capabilityId"],
    "requestSha256": bilateral["requestSha256"],
    "outcomeSha256": bilateral["outcomeSha256"],
    "localReceiptSha256": bilateral["localReceiptSha256"],
    "remoteReceiptSha256": bilateral["remoteReceiptSha256"],
    "signerKernelIds": bilateral["signerKernelIds"],
}
bilateral_invocation_hash = canonical_hash(binding_payload)
lineage["bilateralInvocationSha256"] = bilateral_invocation_hash
lineage_hash = canonical_hash(lineage)
bilateral["lineageStatementSha256"] = lineage_hash
asserted = dict(lineage)
asserted["evidenceClass"] = "asserted"

write_json(lineage_path, lineage)
write_json(bilateral_path, bilateral)
write_json(asserted_path, asserted)
print(bilateral_invocation_hash)
print(lineage_hash)
PY
}

write_bilateral_for_intersection() {
  local intersection_hash="$1"
  local continuation_hash
  continuation_hash="$(canonical_hash "$tmpdir/continuation.json")"
  local lineage_hash
  lineage_hash="$(canonical_hash "$tmpdir/lineage.json")"
  cat >"$tmpdir/bilateral.json" <<JSON
{
  "schema": "chio.federation.bilateral-invocation.v1",
  "invocationId": "invoke-1",
  "treatyId": "treaty-buyer-vendor",
  "ladderIntersectionSha256": "${intersection_hash}",
  "continuationSha256": "${continuation_hash}",
  "lineageStatementSha256": "${lineage_hash}",
  "actionClassId": "workflow.destructive.vendor_call",
  "consistencyModel": "totally-ordered",
  "capabilityId": "cap-live-1",
  "requestSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "outcomeSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "localReceiptSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "remoteReceiptSha256": "3333333333333333333333333333333333333333333333333333333333333333",
  "signerKernelIds": ["kernel.buyer", "kernel.vendor-b"]
}
JSON
  rebind_lineage_and_bilateral
}

write_common_fixtures() {
  cat >"$tmpdir/buyer-ladder.json" <<'JSON'
{
  "schema": "chio.federation.governance-ladder-manifest.v1",
  "manifestId": "ladder-kernel-buyer",
  "kernelId": "kernel.buyer",
  "issuer": "did:chio:kernel.buyer",
  "keyId": "ladder-key-1",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "destructiveFloor": "receipt_backed",
  "defaultUnknownMode": "deny",
  "actionClasses": [
    {
      "actionClassId": "workflow.destructive.vendor_call",
      "mode": "receipt_backed",
      "destructive": true,
      "consistencyModel": "totally-ordered",
      "coSign": "bilateral_required",
      "evidenceRequired": ["governance_receipt", "bilateral_invocation", "receipt_lineage"],
      "aliases": []
    }
  ]
}
JSON
  cat >"$tmpdir/vendor-ladder.json" <<'JSON'
{
  "schema": "chio.federation.governance-ladder-manifest.v1",
  "manifestId": "ladder-kernel-vendor-b",
  "kernelId": "kernel.vendor-b",
  "issuer": "did:chio:kernel.vendor-b",
  "keyId": "ladder-key-1",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "destructiveFloor": "receipt_backed",
  "defaultUnknownMode": "deny",
  "actionClasses": [
    {
      "actionClassId": "workflow.destructive.vendor_call",
      "mode": "receipt_backed",
      "destructive": true,
      "consistencyModel": "totally-ordered",
      "coSign": "bilateral_required",
      "evidenceRequired": ["governance_receipt", "bilateral_invocation"],
      "aliases": []
    }
  ]
}
JSON
  local buyer_hash
  buyer_hash="$(canonical_hash "$tmpdir/buyer-ladder.json")"
  local vendor_hash
  vendor_hash="$(canonical_hash "$tmpdir/vendor-ladder.json")"
  cat >"$tmpdir/treaty-scope.json" <<JSON
{
  "schema": "chio.federation.treaty-scope.v1",
  "treatyId": "treaty-buyer-vendor",
  "participantKernelIds": ["kernel.buyer", "kernel.vendor-b"],
  "participantPublicKeys": [
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",
    "511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a"
  ],
  "ladderManifestSha256s": ["${buyer_hash}", "${vendor_hash}"],
  "allowedActionClasses": ["workflow.destructive.vendor_call"],
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "revocationEpochSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "trustBundleSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}
JSON
  cat >"$tmpdir/continuation.json" <<'JSON'
{
  "schema": "chio.federation.cross-kernel-continuation.v1",
  "continuationId": "continue-1",
  "sourceKernelId": "kernel.buyer",
  "targetKernelId": "kernel.vendor-b",
  "parentReceiptSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "parentSessionAnchorSha256": "2222222222222222222222222222222222222222222222222222222222222222",
  "capabilityId": "cap-live-1",
  "actionClassId": "workflow.destructive.vendor_call",
  "audienceTool": "vendor-ledger.close_account",
  "nonce": "nonce-1",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000
}
JSON
  local continuation_hash
  continuation_hash="$(canonical_hash "$tmpdir/continuation.json")"
  cat >"$tmpdir/lineage.json" <<JSON
{
  "schema": "chio.federation.receipt-lineage-statement.v1",
  "statementId": "lineage-1",
  "parentReceiptSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "childReceiptSha256": "3333333333333333333333333333333333333333333333333333333333333333",
  "continuationSha256": "${continuation_hash}",
  "bilateralInvocationSha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "evidenceClass": "verified",
  "sourceKernelId": "kernel.buyer",
  "targetKernelId": "kernel.vendor-b"
}
JSON
  local lineage_hash
  lineage_hash="$(canonical_hash "$tmpdir/lineage.json")"
  cat >"$tmpdir/bilateral.json" <<JSON
{
  "schema": "chio.federation.bilateral-invocation.v1",
  "invocationId": "invoke-1",
  "treatyId": "treaty-buyer-vendor",
  "ladderIntersectionSha256": "6666666666666666666666666666666666666666666666666666666666666666",
  "continuationSha256": "${continuation_hash}",
  "lineageStatementSha256": "${lineage_hash}",
  "actionClassId": "workflow.destructive.vendor_call",
  "consistencyModel": "totally-ordered",
  "capabilityId": "cap-live-1",
  "requestSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "outcomeSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "localReceiptSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "remoteReceiptSha256": "3333333333333333333333333333333333333333333333333333333333333333",
  "signerKernelIds": ["kernel.buyer", "kernel.vendor-b"]
}
JSON
  local rebind_output
  rebind_output="$(rebind_lineage_and_bilateral)"
  local bilateral_invocation_hash
  bilateral_invocation_hash="$(printf '%s\n' "$rebind_output" | sed -n '1p')"
  lineage_hash="$(printf '%s\n' "$rebind_output" | sed -n '2p')"
  cat >"$tmpdir/packet.json" <<JSON
{
  "schema": "chio.attest.buyer-attestation-packet.v1",
  "packetId": "buyer-packet-1",
  "buyerId": "kernel.buyer",
  "capabilityId": "cap-live-1",
  "treatyScopeSha256": "5555555555555555555555555555555555555555555555555555555555555555",
  "ladderIntersectionSha256": "6666666666666666666666666666666666666666666666666666666666666666",
  "crossBoundaryAdmissionReportSha256": "7777777777777777777777777777777777777777777777777777777777777777",
  "continuationSha256": "${continuation_hash}",
  "receiptLineageStatementSha256": "${lineage_hash}",
  "bilateralInvocationSha256": "${bilateral_invocation_hash}",
  "bilateralDsseSha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "workflowReceiptSha256": "8888888888888888888888888888888888888888888888888888888888888888",
  "proofPackageSha256": "9999999999999999999999999999999999999999999999999999999999999999",
  "verifierReportSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "budgetRefs": ["budget.reserve:local-demo"],
  "settlementClaimed": false
}
JSON
  python3 - "$tmpdir/lineage.json" "$tmpdir/lineage-asserted.json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)
value["evidenceClass"] = "asserted"
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2)
    handle.write("\n")
PY
  cat >"$tmpdir/negative-corpus.json" <<'JSON'
{
  "schema": "chio.federation.treaty-negative-fixture-corpus.v1",
  "cases": [
    { "caseId": "missing-evidence", "expectedCode": "chio_federation_treaty_missing_required_evidence" },
    { "caseId": "asserted-lineage", "expectedCode": "chio_attest_buyer_packet_lineage_not_verified" }
  ]
}
JSON
}

write_packet_for_admission() {
  local admission_path="$1"
  local admission_hash
  admission_hash="$(canonical_hash "$admission_path")"
  local treaty_hash
  treaty_hash="$(python3 - "$admission_path" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["treatyScopeSha256"])
PY
)"
  local intersection_hash
  intersection_hash="$(python3 - "$admission_path" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["ladderIntersectionSha256"])
PY
)"
  local continuation_hash
  continuation_hash="$(canonical_hash "$tmpdir/continuation.json")"
  local rebind_output
  rebind_output="$(write_bilateral_for_intersection "$intersection_hash")"
  local bilateral_invocation_hash
  bilateral_invocation_hash="$(printf '%s\n' "$rebind_output" | sed -n '1p')"
  local lineage_hash
  lineage_hash="$(printf '%s\n' "$rebind_output" | sed -n '2p')"
  cat >"$tmpdir/packet.json" <<JSON
{
  "schema": "chio.attest.buyer-attestation-packet.v1",
  "packetId": "buyer-packet-1",
  "buyerId": "kernel.buyer",
  "capabilityId": "cap-live-1",
  "treatyScopeSha256": "${treaty_hash}",
  "ladderIntersectionSha256": "${intersection_hash}",
  "crossBoundaryAdmissionReportSha256": "${admission_hash}",
  "continuationSha256": "${continuation_hash}",
  "receiptLineageStatementSha256": "${lineage_hash}",
  "bilateralInvocationSha256": "${bilateral_invocation_hash}",
  "bilateralDsseSha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "workflowReceiptSha256": "8888888888888888888888888888888888888888888888888888888888888888",
  "proofPackageSha256": "9999999999999999999999999999999999999999999999999999999999999999",
  "verifierReportSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "budgetRefs": ["budget.reserve:local-demo"],
  "settlementClaimed": false
}
JSON
}

run_schema_flow() {
  write_common_fixtures
  validate_schema "$federation_schema_dir/governance-ladder-manifest.schema.json" "$tmpdir/buyer-ladder.json"
  validate_schema "$federation_schema_dir/governance-ladder-manifest.schema.json" "$tmpdir/vendor-ladder.json"
  validate_schema "$federation_schema_dir/treaty-scope.schema.json" "$tmpdir/treaty-scope.json"
  validate_schema "$federation_schema_dir/cross-kernel-continuation.schema.json" "$tmpdir/continuation.json"
  validate_schema "$federation_schema_dir/receipt-lineage-statement.schema.json" "$tmpdir/lineage.json"
  validate_schema "$federation_schema_dir/bilateral-invocation.schema.json" "$tmpdir/bilateral.json"
  validate_schema "$attest_schema_dir/buyer-attestation-packet.schema.json" "$tmpdir/packet.json"
  validate_schema "$federation_schema_dir/treaty-negative-fixture-corpus.schema.json" "$tmpdir/negative-corpus.json"
}

run_provenance_binding_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- federation treaty intersect \
    --treaty-scope "$tmpdir/treaty-scope.json" \
    --manifest "$tmpdir/buyer-ladder.json" \
    --manifest "$tmpdir/vendor-ladder.json" \
    --now-unix-ms 1800000010000 \
    --report "$tmpdir/intersection.json" >/dev/null
  validate_schema "$federation_schema_dir/ladder-intersection.schema.json" "$tmpdir/intersection.json"
  local intersection_hash
  intersection_hash="$(canonical_hash "$tmpdir/intersection.json")"
  local rebind_output
  rebind_output="$(write_bilateral_for_intersection "$intersection_hash")"
  local bilateral_invocation_hash
  bilateral_invocation_hash="$(printf '%s\n' "$rebind_output" | sed -n '1p')"
  local lineage_hash
  lineage_hash="$(printf '%s\n' "$rebind_output" | sed -n '2p')"
  cargo run -p chio-cli -- federation treaty admit \
    --treaty-scope "$tmpdir/treaty-scope.json" \
    --ladder-intersection "$tmpdir/intersection.json" \
    --expected-ladder-intersection-sha256 "$intersection_hash" \
    --action-class-id "workflow.destructive.vendor_call" \
    --evidence governance_receipt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
    --evidence bilateral_invocation="$bilateral_invocation_hash" \
    --evidence receipt_lineage="$lineage_hash" \
    --now-unix-ms 1800000010000 \
    --report "$tmpdir/admission.json" >/dev/null
  validate_schema "$federation_schema_dir/cross-boundary-admission-report.schema.json" "$tmpdir/admission.json"
  grep -q '"accepted": true' "$tmpdir/admission.json"
  write_packet_for_admission "$tmpdir/admission.json"
  validate_schema "$federation_schema_dir/bilateral-invocation.schema.json" "$tmpdir/bilateral.json"
  validate_schema "$attest_schema_dir/buyer-attestation-packet.schema.json" "$tmpdir/packet.json"
  if cargo run -p chio-cli -- federation treaty verify-packet \
    --packet "$tmpdir/packet.json" \
    --lineage-statement "$tmpdir/lineage.json" \
    --continuation "$tmpdir/continuation.json" \
    --admission-report "$tmpdir/admission.json" \
    --bilateral-invocation "$tmpdir/bilateral.json" \
    --report "$tmpdir/packet-report.json" >/dev/null; then
    echo "expected unresolved proof package verification to reject" >&2
    exit 1
  fi
  validate_schema "$attest_schema_dir/buyer-attestation-verification-report.schema.json" "$tmpdir/packet-report.json"
  grep -q '"verificationState": "unresolved"' "$tmpdir/packet-report.json"
  grep -q '"accepted": false' "$tmpdir/packet-report.json"
  grep -q '"failureCode": "chio_attest_buyer_packet_dsse_unresolved"' "$tmpdir/packet-report.json"
}

run_negative_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- federation treaty intersect \
    --treaty-scope "$tmpdir/treaty-scope.json" \
    --manifest "$tmpdir/buyer-ladder.json" \
    --manifest "$tmpdir/vendor-ladder.json" \
    --now-unix-ms 1800000010000 \
    --report "$tmpdir/intersection.json" >/dev/null
  local intersection_hash
  intersection_hash="$(canonical_hash "$tmpdir/intersection.json")"
  local rebind_output
  rebind_output="$(write_bilateral_for_intersection "$intersection_hash")"
  local bilateral_invocation_hash
  bilateral_invocation_hash="$(printf '%s\n' "$rebind_output" | sed -n '1p')"
  local lineage_hash
  lineage_hash="$(printf '%s\n' "$rebind_output" | sed -n '2p')"
  if cargo run -p chio-cli -- federation treaty admit \
    --treaty-scope "$tmpdir/treaty-scope.json" \
    --ladder-intersection "$tmpdir/intersection.json" \
    --expected-ladder-intersection-sha256 "$intersection_hash" \
    --action-class-id "workflow.destructive.vendor_call" \
    --evidence governance_receipt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
    --now-unix-ms 1800000010000 \
    --report "$tmpdir/admission-negative.json" >/dev/null; then
    echo "expected incomplete treaty admission to reject" >&2
    exit 1
  fi
  validate_schema "$federation_schema_dir/cross-boundary-admission-report.schema.json" "$tmpdir/admission-negative.json"
  grep -q '"accepted": false' "$tmpdir/admission-negative.json"
  grep -q '"failureCode": "chio_federation_treaty_missing_required_evidence"' "$tmpdir/admission-negative.json"
  cargo run -p chio-cli -- federation treaty admit \
    --treaty-scope "$tmpdir/treaty-scope.json" \
    --ladder-intersection "$tmpdir/intersection.json" \
    --expected-ladder-intersection-sha256 "$intersection_hash" \
    --action-class-id "workflow.destructive.vendor_call" \
    --evidence governance_receipt=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
    --evidence bilateral_invocation="$bilateral_invocation_hash" \
    --evidence receipt_lineage="$lineage_hash" \
    --now-unix-ms 1800000010000 \
    --report "$tmpdir/admission.json" >/dev/null
  write_packet_for_admission "$tmpdir/admission.json"
  if cargo run -p chio-cli -- federation treaty verify-packet \
    --packet "$tmpdir/packet.json" \
    --lineage-statement "$tmpdir/lineage-asserted.json" \
    --continuation "$tmpdir/continuation.json" \
    --admission-report "$tmpdir/admission.json" \
    --bilateral-invocation "$tmpdir/bilateral.json" \
    --report "$tmpdir/packet-negative.json" >/dev/null; then
    echo "expected asserted lineage proof package verification to reject" >&2
    exit 1
  fi
  validate_schema "$attest_schema_dir/buyer-attestation-verification-report.schema.json" "$tmpdir/packet-negative.json"
  grep -q '"accepted": false' "$tmpdir/packet-negative.json"
  grep -q '"failureCode": "chio_attest_buyer_packet_lineage_not_verified"' "$tmpdir/packet-negative.json"
}

case "$MODE" in
  "schema-only")
    run_schema_flow
    ;;
  "negative-only")
    run_negative_flow
    ;;
  "full")
    run_schema_flow
    run_provenance_binding_flow
    run_negative_flow
    cargo test -p chio-runtime-core treaty_ --test runtime_admission
    cargo test -p chio-runtime-core buyer_attestation --test runtime_buyer_review
    ;;
esac
