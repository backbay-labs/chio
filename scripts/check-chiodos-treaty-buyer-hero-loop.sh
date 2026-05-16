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
  "--runtime-only")
    MODE="runtime-only"
    ;;
  "--packet-only")
    MODE="packet-only"
    ;;
  "--explain-only")
    MODE="explain-only"
    ;;
  *)
    echo "usage: check-chiodos-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chiodos-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
schema_dir="$repo_root/spec/schemas/chiodos/v1"
fixture_dir="$repo_root/examples/chiodos-3vendor/fixtures"
tmpdir="$(mktemp -d)"
trap 'if [[ "${CHIODOS_KEEP_TMP:-0}" == "1" ]]; then echo "kept tmpdir: $tmpdir" >&2; else rm -rf "$tmpdir"; fi' EXIT

run_chio() {
  if [[ -n "${CHIO_BIN:-}" ]]; then
    "$CHIO_BIN" "$@"
  else
    cargo run -p chio-cli -- "$@"
  fi
}

run_spec_validate() {
  if [[ -n "${CHIO_SPEC_VALIDATE_BIN:-}" ]]; then
    "$CHIO_SPEC_VALIDATE_BIN" "$@"
  else
    cargo run -p chio-spec-validate -- "$@"
  fi
}

validate_schema() {
  run_spec_validate "$1" "$2" >/dev/null
}

run_strict_dsse_negative_tests() {
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_missing_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_non_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available --test runtime_buyer_review
  cargo test -p chio-federation strict_chiodos_treaty_review_binds_live_material --lib
}

runtime_spine_tmpdir=""

run_runtime_spine_with_artifacts() {
  local mode_arg="${1:-}"
  local log_file="$tmpdir/runtime-spine.log"
  local keep_tmp="${CHIODOS_KEEP_TMP:-0}"
  if [[ -n "$mode_arg" ]]; then
    CHIODOS_KEEP_TMP=1 bash "$repo_root/scripts/check-chiodos-runtime-spine.sh" "$mode_arg" >"$log_file" 2>&1
  else
    CHIODOS_KEEP_TMP=1 bash "$repo_root/scripts/check-chiodos-runtime-spine.sh" >"$log_file" 2>&1
  fi
  cat "$log_file"
  runtime_spine_tmpdir="$(sed -n 's/^kept tmpdir: //p' "$log_file" | tail -n 1)"
  if [[ -z "$runtime_spine_tmpdir" || ! -d "$runtime_spine_tmpdir" ]]; then
    echo "runtime spine did not expose kept artifacts" >&2
    exit 1
  fi
  if [[ "$keep_tmp" != "1" ]]; then
    trap 'rm -rf "$tmpdir" "$runtime_spine_tmpdir"' EXIT
  fi
}

if [[ "$MODE" == "packet-only" ]]; then
  run_runtime_spine_with_artifacts
  exit 0
fi

if [[ "$MODE" == "explain-only" ]]; then
  run_runtime_spine_with_artifacts
  run_chio chiodos buyer explain \
    --report "$runtime_spine_tmpdir/loopback-out/buyer-review-report.json" \
    --format text \
    --out "$tmpdir/review.txt"
  grep -q "Accepted: true" "$tmpdir/review.txt"
  grep -q "Verification state: strict_verified" "$tmpdir/review.txt"
  exit 0
fi

if [[ "$MODE" == "negative-only" ]]; then
  run_runtime_spine_with_artifacts --negative-only
  run_strict_dsse_negative_tests
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_buyer_review
  exit 0
fi

if [[ "$MODE" == "full" ]]; then
  bash "$0" --schema-only
  bash "$0" --packet-only
  bash "$0" --explain-only
  bash "$0" --negative-only
  exit 0
fi

write_fixtures() {
  mkdir -p "$tmpdir/run"
  cp "$fixture_dir/buyer-auditor-proof-package.json" "$tmpdir/run/proof-package.json"
  cp "$fixture_dir/verifier-report.json" "$tmpdir/run/verifier-report.json"
  python3 - "$tmpdir/run" "$fixture_dir" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import base64

run = pathlib.Path(sys.argv[1])
fixture_dir = pathlib.Path(sys.argv[2])

def write(name, value):
    path = run / name
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path

def canonical_hash_value(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def canonical_hash_file(path):
    return canonical_hash_value(json.loads(path.read_text(encoding="utf-8")))

def artifact_entry(role, name):
    data = (run / name).read_bytes()
    return {
        "role": role,
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byteCount": len(data),
    }

def bilateral_invocation_binding_hash(invocation):
    preimage = {
        "schema": invocation["schema"],
        "invocationId": invocation["invocationId"],
        "treatyId": invocation["treatyId"],
        "ladderIntersectionSha256": invocation["ladderIntersectionSha256"],
        "continuationSha256": invocation["continuationSha256"],
        "actionClassId": invocation["actionClassId"],
        "consistencyModel": invocation["consistencyModel"],
        "capabilityId": invocation["capabilityId"],
        "requestSha256": invocation["requestSha256"],
        "outcomeSha256": invocation["outcomeSha256"],
        "localReceiptSha256": invocation["localReceiptSha256"],
        "remoteReceiptSha256": invocation["remoteReceiptSha256"],
        "signerKernelIds": invocation["signerKernelIds"],
    }
    return canonical_hash_value(preimage)

def dsse_pae(payload_type, payload):
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )

def ed25519_sign_with_seed(seed_byte, message):
    signer = r"""
const crypto = require("crypto");
const seedByte = Number(process.argv[1]);
const chunks = [];
process.stdin.on("data", chunk => chunks.push(chunk));
process.stdin.on("end", () => {
  const seed = Buffer.alloc(32, seedByte);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed
  ]);
  const key = crypto.createPrivateKey({key: pkcs8, format: "der", type: "pkcs8"});
  process.stdout.write(crypto.sign(null, Buffer.concat(chunks), key).toString("base64"));
});
"""
    result = subprocess.run(
        ["node", "-e", signer, str(seed_byte)],
        input=message,
        stdout=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode("ascii")

BUYER_KERNEL_ID = "did:chio:buyer-kernel"
VENDOR_B_KERNEL_ID = "did:chio:vendor-b"
BUYER_PUBLIC_KEY_HEX = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
VENDOR_B_PUBLIC_KEY_HEX = "511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a"
BUYER_KEYID = hashlib.sha256(bytes.fromhex(BUYER_PUBLIC_KEY_HEX)).hexdigest()
VENDOR_B_KEYID = hashlib.sha256(bytes.fromhex(VENDOR_B_PUBLIC_KEY_HEX)).hexdigest()
proof_seed = json.loads((run / "proof-package.json").read_text(encoding="utf-8"))
tool_receipt = proof_seed["toolReceipts"][0]
tool_receipt_id = tool_receipt["id"]
tool_receipt_hash = canonical_hash_value(tool_receipt)
tool_receipt_body = {
    key: value
    for key, value in tool_receipt.items()
    if key not in {"algorithm", "signature"}
}
tool_receipt_body_hash = canonical_hash_value(tool_receipt_body)
lease_body = proof_seed["capabilityLeases"][0]["body"]
lease_id = lease_body["leaseId"]
lease_issuer = lease_body["issuer"]
lease_expires_at_unix_ms = lease_body["expiresAtUnixMs"]
lease_scope_digest = lease_body["scopeDigest"]
governance_receipt = proof_seed["governanceReceipts"][0]
governance_body = governance_receipt["body"]
governance_receipt_id = governance_body["receiptId"]
governance_kernel_id = governance_body.get("authorizingKernel", governance_body.get("kernelId"))
governance_digest = governance_receipt.get("digest", canonical_hash_value(governance_receipt))

continuation = {
    "schema": "chio.chiodos.cross-kernel-continuation.v1",
    "continuationId": "continue-1",
    "sourceKernelId": "kernel.buyer",
    "targetKernelId": "kernel.vendor-b",
    "parentReceiptSha256": "1" * 64,
    "parentSessionAnchorSha256": "2" * 64,
    "capabilityId": "cap-live-1",
    "actionClassId": "workflow.destructive.vendor_call",
    "audienceTool": "vendor-ledger.close_account",
    "nonce": "nonce-1",
    "issuedAtUnixMs": 1800000000000,
    "expiresAtUnixMs": 1800003600000,
}
continuation_path = write("cross-kernel-continuation.json", continuation)
continuation_hash = canonical_hash_file(continuation_path)

lineage = {
    "schema": "chio.chiodos.receipt-lineage-statement.v1",
    "statementId": "lineage-1",
    "parentReceiptSha256": "1" * 64,
    "childReceiptSha256": tool_receipt_hash,
    "continuationSha256": continuation_hash,
    "bilateralInvocationSha256": "4" * 64,
    "evidenceClass": "verified",
    "sourceKernelId": "kernel.buyer",
    "targetKernelId": "kernel.vendor-b",
}
lineage_path = write("receipt-lineage-statement.json", lineage)
lineage_hash = canonical_hash_file(lineage_path)
lineage_bundle = {
    "schema": "chio.chiodos.receipt-lineage-bundle.v1",
    "bundleId": "lineage-bundle-1",
    "rootReceiptSha256": lineage["parentReceiptSha256"],
    "leafReceiptSha256": lineage["childReceiptSha256"],
    "statements": [lineage],
}
lineage_bundle_path = write("receipt-lineage-bundle.json", lineage_bundle)
lineage_bundle_hash = canonical_hash_file(lineage_bundle_path)

admission = {
    "schema": "chio.chiodos.cross-boundary-admission-report.v1",
    "treatyId": "treaty-buyer-vendor",
    "actionClassId": "workflow.destructive.vendor_call",
    "accepted": True,
    "mode": "receipt_backed",
    "consistencyModel": "totally_ordered",
    "coSign": "bilateral_required",
    "requiredEvidence": ["governance_receipt", "bilateral_invocation", "receipt_lineage"],
    "presentEvidence": ["governance_receipt", "bilateral_invocation", "receipt_lineage"],
    "verifiedEvidence": [
        {"evidenceClass": "governance_receipt", "artifactSha256": "d" * 64, "verified": True},
        {"evidenceClass": "bilateral_invocation", "artifactSha256": "4" * 64, "verified": True},
        {"evidenceClass": "receipt_lineage", "artifactSha256": lineage_hash, "verified": True},
    ],
    "treatyScopeSha256": "5" * 64,
    "ladderIntersectionSha256": "6" * 64,
    "expectedLadderIntersectionSha256": "6" * 64,
    "checks": ["chiodos_treaty.required_evidence_present"],
}
admission_path = write("cross-boundary-admission-report.json", admission)
admission_hash = canonical_hash_file(admission_path)

bilateral = {
    "schema": "chio.chiodos.bilateral-invocation.v1",
    "invocationId": tool_receipt_id,
    "treatyId": "treaty-buyer-vendor",
    "ladderIntersectionSha256": "6" * 64,
    "continuationSha256": continuation_hash,
    "lineageStatementSha256": lineage_hash,
    "actionClassId": "workflow.destructive.vendor_call",
    "consistencyModel": "totally_ordered",
    "capabilityId": "cap-live-1",
    "requestSha256": "b" * 64,
    "outcomeSha256": "c" * 64,
    "localReceiptSha256": "1" * 64,
    "remoteReceiptSha256": tool_receipt_hash,
    "signerKernelIds": [BUYER_KERNEL_ID, VENDOR_B_KERNEL_ID],
}
bilateral_binding_hash = bilateral_invocation_binding_hash(bilateral)
lineage["bilateralInvocationSha256"] = bilateral_binding_hash
lineage_path = write("receipt-lineage-statement.json", lineage)
lineage_hash = canonical_hash_file(lineage_path)
lineage_bundle["statements"] = [lineage]
lineage_bundle_path = write("receipt-lineage-bundle.json", lineage_bundle)
lineage_bundle_hash = canonical_hash_file(lineage_bundle_path)
admission["verifiedEvidence"][2]["artifactSha256"] = lineage_hash
admission["verifiedEvidence"][1]["artifactSha256"] = bilateral_binding_hash
admission_path = write("cross-boundary-admission-report.json", admission)
admission_hash = canonical_hash_file(admission_path)
bilateral["lineageStatementSha256"] = lineage_hash
write("bilateral-invocation.json", bilateral)

dsse_statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {"name": f"chio-receipt:{tool_receipt_id}", "digest": {"sha256": tool_receipt_body_hash}}
    ],
    "predicateType": "chio.bilateral-cosign-invocation.v1",
    "predicate": {
        "invocation_id": tool_receipt_id,
        "tool_server_a": {
            "kernel_id": BUYER_KERNEL_ID,
            "passport_key_fingerprint": BUYER_KEYID,
            "alg": "ed25519",
        },
        "tool_server_b": {
            "kernel_id": VENDOR_B_KERNEL_ID,
            "passport_key_fingerprint": VENDOR_B_KEYID,
            "alg": "ed25519",
        },
        "tool_name": "vendor-ledger.close_account",
        "co_sign": "bilateral_required",
        "consistency_model": "totally_ordered",
        "cross_org_visibility": "treaty_only",
        "timestamp_unix_ms": 1800000010000,
        "tool_args_hash": {"alg": "sha256", "value": "b" * 64},
        "capability_lease_ref": {
            "lease_id": lease_id,
            "issuer": lease_issuer,
            "expires_at_unix_ms": lease_expires_at_unix_ms,
            "scope_digest": {"alg": "sha256", "value": lease_scope_digest},
        },
        "policy_evaluation_summary": {
            "server_a_verdict": {
                "verdict": "allow",
                "policy_id": "policy-buyer",
                "policy_version": "v1",
            },
            "server_b_verdict": {
                "verdict": "allow",
                "policy_id": "policy-vendor",
                "policy_version": "v1",
            },
            "joint_disposition": "allow",
        },
        "governance_receipt_ref": {
            "receipt_id": governance_receipt_id,
            "kernel_id": governance_kernel_id,
            "digest": {"alg": "sha256", "value": governance_digest},
        },
        "consistency_anchor": "anchor-live",
        "treaty_binding_ref": {
            "treaty_id": "treaty-buyer-vendor",
            "treaty_scope_sha256": "5" * 64,
            "ladder_intersection_sha256": "6" * 64,
            "admission_report_sha256": admission_hash,
            "continuation_sha256": continuation_hash,
            "lineage_bundle_sha256": lineage_bundle_hash,
            "action_class_id": "workflow.destructive.vendor_call",
            "consistency_model": "totally_ordered",
            "request_sha256": "b" * 64,
            "outcome_sha256": "c" * 64,
            "local_receipt_sha256": "1" * 64,
            "remote_receipt_sha256": tool_receipt_hash,
            "lease_refs": [lease_id],
            "governance_refs": [governance_receipt_id],
            "signer_kernel_ids": [BUYER_KERNEL_ID, VENDOR_B_KERNEL_ID],
        },
    },
}
dsse_payload = json.dumps(dsse_statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
dsse_pae_bytes = dsse_pae("application/vnd.in-toto+json", dsse_payload)
dsse_envelope = {
    "payloadType": "application/vnd.in-toto+json",
    "payload": base64.b64encode(dsse_payload).decode("ascii"),
    "signatures": [
        {
            "keyid": BUYER_KEYID,
            "sig": ed25519_sign_with_seed(11, dsse_pae_bytes),
        },
        {
            "keyid": VENDOR_B_KEYID,
            "sig": ed25519_sign_with_seed(22, dsse_pae_bytes),
        },
    ],
}
write("bilateral-dsse-envelope.json", dsse_envelope)

proof = json.loads((run / "proof-package.json").read_text(encoding="utf-8"))
workflow_receipt = proof["workflowReceipt"]
proof.pop("treatyBilateralEnvelopes", None)
bilateral_envelopes = proof.setdefault("bilateralEnvelopes", [])
if bilateral_envelopes:
    bilateral_envelopes[0] = dsse_envelope
else:
    bilateral_envelopes.append(dsse_envelope)
workflow_receipt["steps"][0]["bilateral_dsse_sha256"] = canonical_hash_value(dsse_envelope)
workflow_receipt["steps"][0]["consistency_anchor"] = "anchor-live"
workflow_path = write("workflow-receipt.json", workflow_receipt)
proof["workflowReceipt"] = workflow_receipt
write("proof-package.json", proof)
workflow_step_hash = canonical_hash_value(workflow_receipt["steps"][0])
source_record = {
    "stepIndex": 0,
    "admissionReportSha256": admission_hash,
    "toolReceiptSha256": tool_receipt_hash,
    "bilateralDsseSha256": canonical_hash_file(run / "bilateral-dsse-envelope.json"),
    "workflowStepSha256": workflow_step_hash,
}
proof_regeneration_report = {
    "schema": "chio.chiodos.runtime-proof-regeneration-report.v1",
    "runId": "run-live-1",
    "accepted": True,
    "generatedAtUnixMs": 1800000010000,
    "proofPackageSha256": canonical_hash_file(run / "proof-package.json"),
    "verifierReportSha256": canonical_hash_file(run / "verifier-report.json"),
    "workflowReceiptSha256": canonical_hash_file(workflow_path),
    "sourceRecords": [source_record],
    "checks": ["runtime_proof.regenerated"],
}
proof_regeneration_path = write("proof-regeneration-report.json", proof_regeneration_report)
runtime_run_report = {
    "schema": "chio.chiodos.runtime-workflow-run-report.v1",
    "runId": "run-live-1",
    "accepted": True,
    "generatedAtUnixMs": 1800000010000,
    "admissionReportSha256": admission_hash,
    "evidencePaths": [
        "bilateral-dsse-envelope.json",
        "proof-regeneration-report.json",
    ],
    "stepEvidence": [
        {
            "schema": "chio.chiodos.runtime-step-evidence.v1",
            "stepIndex": 0,
            "admissionId": "adm-live-1",
            "admissionReportSha256": admission_hash,
            "toolReceiptId": tool_receipt_id,
            "toolReceiptSha256": tool_receipt_hash,
            "outputSha256": "c" * 64,
            "bilateralDsseSha256": source_record["bilateralDsseSha256"],
            "workflowStepSha256": source_record["workflowStepSha256"],
            "parentReceiptSha256": "1" * 64,
            "consistencyAnchor": "anchor-live",
            "destructive": True,
            "leaseId": lease_id,
            "governanceReceiptId": governance_receipt_id,
        }
    ],
    "proofRegenerationReportSha256": canonical_hash_file(proof_regeneration_path),
}
write("runtime-run-report.json", runtime_run_report)
runtime_run_report_hash = canonical_hash_file(run / "runtime-run-report.json")
proof_regeneration_report_hash = canonical_hash_file(proof_regeneration_path)
runtime_evidence_manifest = {
    "schema": "chio.chiodos.runtime-evidence-manifest.v1",
    "runId": "run-live-1",
    "generatedAtUnixMs": 1800000010000,
    "workflowRunReportSha256": runtime_run_report_hash,
    "proofRegenerationReportSha256": proof_regeneration_report_hash,
    "entries": [
        artifact_entry("bilateral_dsse_envelope", "bilateral-dsse-envelope.json"),
        artifact_entry("workflow_receipt", "workflow-receipt.json"),
        artifact_entry("proof_package", "proof-package.json"),
        artifact_entry("verifier_report", "verifier-report.json"),
        artifact_entry("proof_regeneration_report", "proof-regeneration-report.json"),
        artifact_entry("runtime_run_report", "runtime-run-report.json"),
    ],
}
manifest_path = write("runtime-evidence-manifest.json", runtime_evidence_manifest)
runtime_proof_input = {
    "schema": "chio.chiodos.runtime-proof-regeneration-input.v1",
    "runId": "run-live-1",
    "evidenceManifestSha256": canonical_hash_file(manifest_path),
    "workflowRunReportSha256": runtime_run_report_hash,
    "admissionReportSha256": admission_hash,
    "trustBundleSha256": canonical_hash_file(fixture_dir / "verifier-trust-bundle.json"),
    "verificationContextSha256": canonical_hash_file(fixture_dir / "verification-context.json"),
    "sourceRecords": [source_record],
}
write("runtime-proof-regeneration-input.json", runtime_proof_input)

packet = {
    "schema": "chio.chiodos.buyer-attestation-packet.v1",
    "packetId": "buyer-packet-1",
    "buyerId": "buyer.acme",
    "capabilityId": "cap-live-1",
    "treatyScopeSha256": "5" * 64,
    "ladderIntersectionSha256": "6" * 64,
    "crossBoundaryAdmissionReportSha256": admission_hash,
    "continuationSha256": continuation_hash,
    "receiptLineageStatementSha256": lineage_hash,
    "bilateralInvocationSha256": bilateral_binding_hash,
    "bilateralDsseSha256": canonical_hash_file(run / "bilateral-dsse-envelope.json"),
    "workflowReceiptSha256": canonical_hash_file(workflow_path),
    "proofPackageSha256": canonical_hash_file(run / "proof-package.json"),
    "verifierReportSha256": canonical_hash_file(run / "verifier-report.json"),
    "budgetRefs": ["budget.reserve:local-demo"],
    "settlementClaimed": False,
}
write("buyer-attestation-packet.json", packet)

negative = {
    "schema": "chio.chiodos.treaty-runtime-negative-fixture-corpus.v1",
    "cases": [
        {
            "caseId": "missing-treaty",
            "expectedCode": "chiodos_buyer_review_missing_treaty_dsse_binding",
        },
        {
            "caseId": "stale-treaty",
            "expectedCode": "chiodos_buyer_packet_hash_mismatch",
        },
        {
            "caseId": "forged-intersection",
            "expectedCode": "chiodos_buyer_packet_hash_mismatch",
        },
        {
            "caseId": "compatibility-only-dsse",
            "expectedCode": "chiodos_buyer_review_non_strict_dsse",
        },
        {
            "caseId": "missing-co-signature",
            "expectedCode": "chiodos_buyer_review_strict_dsse_signature_invalid",
        },
        {
            "caseId": "duplicate-dsse-signature-keyid",
            "expectedCode": "chiodos_buyer_review_strict_dsse_signature_invalid",
        },
        {
            "caseId": "receipt-mismatch",
            "expectedCode": "chiodos_treaty_bilateral_mismatch",
        },
        {
            "caseId": "verifier-report-substitution",
            "expectedCode": "chiodos_buyer_review_artifact_hash_mismatch",
        },
        {
            "caseId": "verifier-report-rejected",
            "expectedCode": "chiodos_buyer_review_verifier_report_rejected",
        },
        {
            "caseId": "settlement-claim",
            "expectedCode": "chiodos_buyer_packet_settlement_claimed",
        },
        {
            "caseId": "hidden-predicate-claim",
            "expectedCode": "chiodos_buyer_review_verifier_report_rejected",
        },
        {
            "caseId": "request-smuggled-trust-root",
            "expectedCode": "chiodos_buyer_review_strict_dsse_binding_mismatch",
        },
        {
            "caseId": "dynamic-trust-claim",
            "expectedCode": "chiodos_buyer_review_strict_dsse_binding_mismatch",
        },
    ],
}
write("treaty-runtime-negative-corpus.json", negative)
PY
}

refresh_verifier_report_bindings() {
  run_chio chiodos verify \
    --package "$tmpdir/run/proof-package.json" \
    --trust-bundle "$fixture_dir/verifier-trust-bundle.json" \
    --context "$fixture_dir/verification-context.json" \
    --report "$tmpdir/run/verifier-report.json" >/dev/null
  python3 - "$tmpdir/run" "$fixture_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

run = pathlib.Path(sys.argv[1])
fixture_dir = pathlib.Path(sys.argv[2])

def load(name):
    return json.loads((run / name).read_text(encoding="utf-8"))

def write(name, value):
    (run / name).write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")

def canonical_hash_value(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def canonical_hash_file(name):
    return canonical_hash_value(load(name))

def canonical_hash_path(path):
    return canonical_hash_value(json.loads(path.read_text(encoding="utf-8")))

def artifact_entry(role, name):
    data = (run / name).read_bytes()
    return {
        "role": role,
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byteCount": len(data),
    }

def bilateral_invocation_binding_hash(invocation):
    preimage = {
        "schema": invocation["schema"],
        "invocationId": invocation["invocationId"],
        "treatyId": invocation["treatyId"],
        "ladderIntersectionSha256": invocation["ladderIntersectionSha256"],
        "continuationSha256": invocation["continuationSha256"],
        "actionClassId": invocation["actionClassId"],
        "consistencyModel": invocation["consistencyModel"],
        "capabilityId": invocation["capabilityId"],
        "requestSha256": invocation["requestSha256"],
        "outcomeSha256": invocation["outcomeSha256"],
        "localReceiptSha256": invocation["localReceiptSha256"],
        "remoteReceiptSha256": invocation["remoteReceiptSha256"],
        "signerKernelIds": invocation["signerKernelIds"],
    }
    return canonical_hash_value(preimage)

proof_regeneration_report = load("proof-regeneration-report.json")
proof_regeneration_report["proofPackageSha256"] = canonical_hash_file("proof-package.json")
proof_regeneration_report["verifierReportSha256"] = canonical_hash_file("verifier-report.json")
proof_regeneration_report["workflowReceiptSha256"] = canonical_hash_file("workflow-receipt.json")
write("proof-regeneration-report.json", proof_regeneration_report)

runtime_run_report = load("runtime-run-report.json")
runtime_run_report["proofRegenerationReportSha256"] = canonical_hash_file("proof-regeneration-report.json")
write("runtime-run-report.json", runtime_run_report)
runtime_run_report_hash = canonical_hash_file("runtime-run-report.json")
proof_regeneration_report_hash = canonical_hash_file("proof-regeneration-report.json")

runtime_evidence_manifest = load("runtime-evidence-manifest.json")
runtime_evidence_manifest["workflowRunReportSha256"] = runtime_run_report_hash
runtime_evidence_manifest["proofRegenerationReportSha256"] = proof_regeneration_report_hash
runtime_evidence_manifest["entries"] = [
    artifact_entry("bilateral_dsse_envelope", "bilateral-dsse-envelope.json"),
    artifact_entry("workflow_receipt", "workflow-receipt.json"),
    artifact_entry("proof_package", "proof-package.json"),
    artifact_entry("verifier_report", "verifier-report.json"),
    artifact_entry("proof_regeneration_report", "proof-regeneration-report.json"),
    artifact_entry("runtime_run_report", "runtime-run-report.json"),
]
write("runtime-evidence-manifest.json", runtime_evidence_manifest)

runtime_proof_input = load("runtime-proof-regeneration-input.json")
runtime_proof_input["evidenceManifestSha256"] = canonical_hash_file("runtime-evidence-manifest.json")
runtime_proof_input["workflowRunReportSha256"] = runtime_run_report_hash
runtime_proof_input["admissionReportSha256"] = canonical_hash_file("cross-boundary-admission-report.json")
runtime_proof_input["trustBundleSha256"] = canonical_hash_path(fixture_dir / "verifier-trust-bundle.json")
runtime_proof_input["verificationContextSha256"] = canonical_hash_path(fixture_dir / "verification-context.json")
runtime_proof_input["sourceRecords"] = proof_regeneration_report["sourceRecords"]
write("runtime-proof-regeneration-input.json", runtime_proof_input)

packet = load("buyer-attestation-packet.json")
packet["crossBoundaryAdmissionReportSha256"] = canonical_hash_file("cross-boundary-admission-report.json")
packet["continuationSha256"] = canonical_hash_file("cross-kernel-continuation.json")
packet["receiptLineageStatementSha256"] = canonical_hash_file("receipt-lineage-statement.json")
packet["bilateralInvocationSha256"] = bilateral_invocation_binding_hash(load("bilateral-invocation.json"))
packet["bilateralDsseSha256"] = canonical_hash_file("bilateral-dsse-envelope.json")
packet["workflowReceiptSha256"] = canonical_hash_file("workflow-receipt.json")
packet["proofPackageSha256"] = canonical_hash_file("proof-package.json")
packet["verifierReportSha256"] = canonical_hash_file("verifier-report.json")
write("buyer-attestation-packet.json", packet)
PY
}

negative_case_rows() {
  python3 - "$tmpdir/run/treaty-runtime-negative-corpus.json" "$tmpdir/negative-cases.tsv" <<'PY'
import json
import sys

corpus_path, out_path = sys.argv[1], sys.argv[2]
corpus = json.load(open(corpus_path, "r", encoding="utf-8"))
with open(out_path, "w", encoding="utf-8") as out:
    for case in corpus["cases"]:
        out.write(f"{case['caseId']}\t{case['expectedCode']}\n")
PY
}

review_failure_code() {
  python3 - "$1" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(report.get("failureCode", ""))
PY
}

mutate_negative_case() {
  local case_id="$1"
  local case_dir="$2"
  local phase="$3"
  python3 - "$case_id" "$case_dir" "$phase" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

case_id, case_dir, phase = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]

def load(name):
    return json.load(open(case_dir / name, "r", encoding="utf-8"))

def write(name, value):
    with open(case_dir / name, "w", encoding="utf-8") as out:
        json.dump(value, out, indent=2)
        out.write("\n")

def canonical_hash_value(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def canonical_hash_file(name):
    return canonical_hash_value(load(name))

def artifact_entry(role, name):
    data = (case_dir / name).read_bytes()
    return {
        "role": role,
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byteCount": len(data),
    }

def bilateral_invocation_binding_hash(invocation):
    preimage = {
        "schema": invocation["schema"],
        "invocationId": invocation["invocationId"],
        "treatyId": invocation["treatyId"],
        "ladderIntersectionSha256": invocation["ladderIntersectionSha256"],
        "continuationSha256": invocation["continuationSha256"],
        "actionClassId": invocation["actionClassId"],
        "consistencyModel": invocation["consistencyModel"],
        "capabilityId": invocation["capabilityId"],
        "requestSha256": invocation["requestSha256"],
        "outcomeSha256": invocation["outcomeSha256"],
        "localReceiptSha256": invocation["localReceiptSha256"],
        "remoteReceiptSha256": invocation["remoteReceiptSha256"],
        "signerKernelIds": invocation["signerKernelIds"],
    }
    return canonical_hash_value(preimage)

def load_dsse_statement():
    envelope = load("bilateral-dsse-envelope.json")
    statement = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
    return envelope, statement

def write_dsse_statement(envelope, statement):
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    envelope["payload"] = base64.b64encode(payload).decode("ascii")
    write("bilateral-dsse-envelope.json", envelope)

def set_packet_hashes(packet):
    packet["crossBoundaryAdmissionReportSha256"] = canonical_hash_file("cross-boundary-admission-report.json")
    packet["continuationSha256"] = canonical_hash_file("cross-kernel-continuation.json")
    packet["receiptLineageStatementSha256"] = canonical_hash_file("receipt-lineage-statement.json")
    packet["bilateralInvocationSha256"] = bilateral_invocation_binding_hash(load("bilateral-invocation.json"))
    packet["bilateralDsseSha256"] = canonical_hash_file("bilateral-dsse-envelope.json")
    packet["workflowReceiptSha256"] = canonical_hash_file("workflow-receipt.json")
    packet["proofPackageSha256"] = canonical_hash_file("proof-package.json")
    packet["verifierReportSha256"] = canonical_hash_file("verifier-report.json")

def refresh_runtime_bindings(update_packet=True):
    proof = load("proof-package.json")
    proof["workflowReceipt"] = load("workflow-receipt.json")
    proof.pop("treatyBilateralEnvelopes", None)
    bilateral_envelopes = proof.setdefault("bilateralEnvelopes", [])
    if bilateral_envelopes:
        bilateral_envelopes[0] = load("bilateral-dsse-envelope.json")
    else:
        bilateral_envelopes.append(load("bilateral-dsse-envelope.json"))
    write("proof-package.json", proof)
    admission_hash = canonical_hash_file("cross-boundary-admission-report.json")
    dsse_hash = canonical_hash_file("bilateral-dsse-envelope.json")
    tool_receipt_hash = canonical_hash_value(proof["toolReceipts"][0])
    tool_receipt_id = proof["toolReceipts"][0]["id"]
    workflow_step_hash = canonical_hash_value(proof["workflowReceipt"]["steps"][0])
    lease_id = proof["capabilityLeases"][0]["body"]["leaseId"]
    governance_receipt_id = proof["governanceReceipts"][0]["body"]["receiptId"]
    source_record = {
        "stepIndex": 0,
        "admissionReportSha256": admission_hash,
        "toolReceiptSha256": tool_receipt_hash,
        "bilateralDsseSha256": dsse_hash,
        "workflowStepSha256": workflow_step_hash,
    }
    proof_regeneration_report = {
        "schema": "chio.chiodos.runtime-proof-regeneration-report.v1",
        "runId": "run-live-1",
        "accepted": True,
        "generatedAtUnixMs": 1800000010000,
        "proofPackageSha256": canonical_hash_file("proof-package.json"),
        "verifierReportSha256": canonical_hash_file("verifier-report.json"),
        "workflowReceiptSha256": canonical_hash_file("workflow-receipt.json"),
        "sourceRecords": [source_record],
        "checks": ["runtime_proof.regenerated"],
    }
    write("proof-regeneration-report.json", proof_regeneration_report)
    runtime_run_report = {
        "schema": "chio.chiodos.runtime-workflow-run-report.v1",
        "runId": "run-live-1",
        "accepted": True,
        "generatedAtUnixMs": 1800000010000,
        "admissionReportSha256": admission_hash,
        "evidencePaths": [
            "bilateral-dsse-envelope.json",
            "proof-regeneration-report.json",
        ],
        "stepEvidence": [
            {
                "schema": "chio.chiodos.runtime-step-evidence.v1",
                "stepIndex": 0,
                "admissionId": "adm-live-1",
                "admissionReportSha256": admission_hash,
                "toolReceiptId": tool_receipt_id,
                "toolReceiptSha256": tool_receipt_hash,
                "outputSha256": "c" * 64,
                "bilateralDsseSha256": dsse_hash,
                "workflowStepSha256": source_record["workflowStepSha256"],
                "parentReceiptSha256": "1" * 64,
                "consistencyAnchor": "anchor-live",
                "destructive": True,
                "leaseId": lease_id,
                "governanceReceiptId": governance_receipt_id,
            }
        ],
        "proofRegenerationReportSha256": canonical_hash_file("proof-regeneration-report.json"),
    }
    write("runtime-run-report.json", runtime_run_report)
    runtime_run_report_hash = canonical_hash_file("runtime-run-report.json")
    proof_regeneration_report_hash = canonical_hash_file("proof-regeneration-report.json")
    runtime_evidence_manifest = {
        "schema": "chio.chiodos.runtime-evidence-manifest.v1",
        "runId": "run-live-1",
        "generatedAtUnixMs": 1800000010000,
        "workflowRunReportSha256": runtime_run_report_hash,
        "proofRegenerationReportSha256": proof_regeneration_report_hash,
        "entries": [
            artifact_entry("bilateral_dsse_envelope", "bilateral-dsse-envelope.json"),
            artifact_entry("workflow_receipt", "workflow-receipt.json"),
            artifact_entry("proof_package", "proof-package.json"),
            artifact_entry("verifier_report", "verifier-report.json"),
            artifact_entry("proof_regeneration_report", "proof-regeneration-report.json"),
            artifact_entry("runtime_run_report", "runtime-run-report.json"),
        ],
    }
    write("runtime-evidence-manifest.json", runtime_evidence_manifest)
    previous_input = load("runtime-proof-regeneration-input.json") if (case_dir / "runtime-proof-regeneration-input.json").exists() else {}
    runtime_proof_input = {
        "schema": "chio.chiodos.runtime-proof-regeneration-input.v1",
        "runId": "run-live-1",
        "evidenceManifestSha256": canonical_hash_file("runtime-evidence-manifest.json"),
        "workflowRunReportSha256": runtime_run_report_hash,
        "admissionReportSha256": admission_hash,
        "trustBundleSha256": previous_input.get("trustBundleSha256", "0" * 64),
        "verificationContextSha256": previous_input.get("verificationContextSha256", "0" * 64),
        "sourceRecords": [source_record],
    }
    write("runtime-proof-regeneration-input.json", runtime_proof_input)
    if update_packet:
        packet = load("buyer-attestation-packet.json")
        set_packet_hashes(packet)
        write("buyer-attestation-packet.json", packet)

def set_dsse_treaty_field(field, value):
    envelope, statement = load_dsse_statement()
    statement["predicate"]["treaty_binding_ref"][field] = value
    write_dsse_statement(envelope, statement)

if case_id == "verifier-report-substitution":
    if phase == "post":
        report = load("verifier-report.json")
        report["accepted"] = False
        write("verifier-report.json", report)
    sys.exit(0)

if phase == "post":
    sys.exit(0)

if case_id == "missing-treaty":
    envelope, statement = load_dsse_statement()
    statement["predicate"].pop("treaty_binding_ref", None)
    write_dsse_statement(envelope, statement)
    refresh_runtime_bindings()
elif case_id == "stale-treaty":
    admission = load("cross-boundary-admission-report.json")
    admission["accepted"] = False
    admission["failureCode"] = "chiodos_treaty_stale"
    admission["checks"].append("chiodos_treaty.stale_rejected")
    write("cross-boundary-admission-report.json", admission)
    packet = load("buyer-attestation-packet.json")
    set_packet_hashes(packet)
    write("buyer-attestation-packet.json", packet)
    set_dsse_treaty_field("admission_report_sha256", packet["crossBoundaryAdmissionReportSha256"])
elif case_id == "forged-intersection":
    admission = load("cross-boundary-admission-report.json")
    admission["ladderIntersectionSha256"] = "a" * 64
    admission["checks"].append("chiodos_treaty.forged_intersection_rejected")
    write("cross-boundary-admission-report.json", admission)
    packet = load("buyer-attestation-packet.json")
    set_packet_hashes(packet)
    write("buyer-attestation-packet.json", packet)
elif case_id == "compatibility-only-dsse":
    envelope, statement = load_dsse_statement()
    statement["predicateType"] = "chio.bilateral-signature-slice.v1"
    write_dsse_statement(envelope, statement)
    refresh_runtime_bindings()
elif case_id == "missing-co-signature":
    envelope = load("bilateral-dsse-envelope.json")
    envelope["signatures"] = envelope["signatures"][:1]
    write("bilateral-dsse-envelope.json", envelope)
    refresh_runtime_bindings()
elif case_id == "duplicate-dsse-signature-keyid":
    envelope = load("bilateral-dsse-envelope.json")
    envelope["signatures"][1]["keyid"] = envelope["signatures"][0]["keyid"]
    write("bilateral-dsse-envelope.json", envelope)
    refresh_runtime_bindings()
elif case_id == "receipt-mismatch":
    bilateral = load("bilateral-invocation.json")
    bilateral["localReceiptSha256"] = "e" * 64
    write("bilateral-invocation.json", bilateral)
elif case_id == "settlement-claim":
    packet = load("buyer-attestation-packet.json")
    packet["settlementClaimed"] = True
    write("buyer-attestation-packet.json", packet)
elif case_id == "hidden-predicate-claim":
    proof = load("proof-package.json")
    proof["claims"]["hiddenRangePredicates"] = True
    write("proof-package.json", proof)
    refresh_runtime_bindings()
elif case_id == "verifier-report-rejected":
    report = load("verifier-report.json")
    report["accepted"] = False
    report["failure"] = {
        "code": "package.claim",
        "phase": "package",
        "detail": "negative verifier report rejected"
    }
    write("verifier-report.json", report)
    refresh_runtime_bindings()
elif case_id == "request-smuggled-trust-root":
    set_dsse_treaty_field("request_sha256", "a" * 64)
    refresh_runtime_bindings()
elif case_id == "dynamic-trust-claim":
    set_dsse_treaty_field("consistency_model", "dynamic_trust")
    refresh_runtime_bindings()
else:
    raise SystemExit(f"unknown negative case {case_id}")
PY
}

run_negative_case() {
  local case_id="$1"
  local expected="$2"
  local case_dir="$3"
  local actual

  rm -rf "$case_dir"
  mkdir -p "$case_dir"
  cp "$tmpdir/run"/*.json "$case_dir"/
  mutate_negative_case "$case_id" "$case_dir" "pre"
  run_chio chiodos buyer package \
    --run-output "$case_dir" \
    --out "$case_dir/review-package.json" >/dev/null
  mutate_negative_case "$case_id" "$case_dir" "post"
  if run_chio chiodos buyer verify \
    --package "$case_dir/review-package.json" \
    --trust-bundle "$fixture_dir/verifier-trust-bundle.json" \
    --context "$fixture_dir/verification-context.json" \
    --report "$case_dir/review-negative.json" >"$case_dir/verify.out" 2>"$case_dir/verify.err"; then
    echo "$case_id unexpectedly passed buyer verification" >&2
    return 1
  fi
  validate_schema "$schema_dir/buyer-attestation-review-report.schema.json" "$case_dir/review-negative.json"
  actual="$(review_failure_code "$case_dir/review-negative.json")"
  if [[ "$actual" != "$expected" ]]; then
    echo "$case_id expected $expected but observed ${actual:-<missing>}" >&2
    return 1
  fi
}

write_fixtures

if [[ "$MODE" == "packet-only" || "$MODE" == "explain-only" || "$MODE" == "negative-only" || "$MODE" == "full" ]]; then
  refresh_verifier_report_bindings
fi

if [[ "$MODE" == "schema-only" || "$MODE" == "full" ]]; then
  validate_schema "$schema_dir/receipt-lineage-bundle.schema.json" "$tmpdir/run/receipt-lineage-bundle.json"
  validate_schema "$schema_dir/proof-package.schema.json" "$tmpdir/run/proof-package.json"
  validate_schema "$schema_dir/treaty-runtime-negative-fixture-corpus.schema.json" "$tmpdir/run/treaty-runtime-negative-corpus.json"
  run_chio chiodos buyer package \
    --run-output "$tmpdir/run" \
    --out "$tmpdir/run/review-package.json"
  validate_schema "$schema_dir/buyer-attestation-review-package.schema.json" "$tmpdir/run/review-package.json"
fi

if [[ "$MODE" == "packet-only" || "$MODE" == "explain-only" || "$MODE" == "full" ]]; then
  run_chio chiodos buyer package \
    --run-output "$tmpdir/run" \
    --out "$tmpdir/run/review-package.json"
  run_chio chiodos buyer verify \
    --package "$tmpdir/run/review-package.json" \
    --trust-bundle "$fixture_dir/verifier-trust-bundle.json" \
    --context "$fixture_dir/verification-context.json" \
    --report "$tmpdir/review-report.json"
  validate_schema "$schema_dir/buyer-attestation-review-report.schema.json" "$tmpdir/review-report.json"
fi

if [[ "$MODE" == "explain-only" || "$MODE" == "full" ]]; then
  run_chio chiodos buyer explain \
    --report "$tmpdir/review-report.json" \
    --format text \
    --out "$tmpdir/review.txt"
  grep -q "Accepted: true" "$tmpdir/review.txt"
  grep -q "Verification state: strict_verified" "$tmpdir/review.txt"
fi

if [[ "$MODE" == "negative-only" || "$MODE" == "full" ]]; then
  run_strict_dsse_negative_tests
  negative_case_rows
  if run_negative_case "verifier-report-substitution" \
    "chiodos_wrong_expected_code_probe" \
    "$tmpdir/wrong-expected-code" >"$tmpdir/wrong-expected-code.out" 2>&1; then
    echo "negative corpus wrong-expected-code detector unexpectedly passed" >&2
    exit 1
  fi
  grep -q "expected chiodos_wrong_expected_code_probe" "$tmpdir/wrong-expected-code.out"
  while IFS=$'\t' read -r case_id expected; do
    run_negative_case "$case_id" "$expected" "$tmpdir/negative-$case_id"
  done < "$tmpdir/negative-cases.tsv"
fi

if [[ "$MODE" == "runtime-only" || "$MODE" == "full" ]]; then
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_buyer_review
  cargo test -p chio-chiodos-runtime receipt_lineage_bundle --test runtime_buyer_review
fi
