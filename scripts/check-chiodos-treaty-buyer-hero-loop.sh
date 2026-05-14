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
trap 'rm -rf "$tmpdir"' EXIT

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

write_fixtures() {
  mkdir -p "$tmpdir/run"
  cp "$fixture_dir/buyer-auditor-proof-package.json" "$tmpdir/run/proof-package.json"
  cp "$fixture_dir/verifier-report.json" "$tmpdir/run/verifier-report.json"
  python3 - "$tmpdir/run" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
import base64

run = pathlib.Path(sys.argv[1])

def write(name, value):
    path = run / name
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path

def canonical_hash_value(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def canonical_hash_file(path):
    return canonical_hash_value(json.loads(path.read_text(encoding="utf-8")))

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
    "childReceiptSha256": "3" * 64,
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
    "requiredEvidence": ["governance_receipt", "bilateral_dsse", "receipt_lineage"],
    "presentEvidence": ["governance_receipt", "bilateral_dsse", "receipt_lineage"],
    "verifiedEvidence": [
        {"evidenceClass": "governance_receipt", "artifactSha256": "d" * 64, "verified": True},
        {"evidenceClass": "bilateral_dsse", "artifactSha256": "4" * 64, "verified": True},
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
    "invocationId": "invoke-1",
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
    "remoteReceiptSha256": "3" * 64,
    "signerKernelIds": [BUYER_KERNEL_ID, VENDOR_B_KERNEL_ID],
}
write("bilateral-invocation.json", bilateral)

dsse_statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {"name": "chio-receipt:invoke-1", "digest": {"sha256": "7" * 64}}
    ],
    "predicateType": "chio.bilateral-cosign-invocation.v1",
    "predicate": {
        "invocation_id": "invoke-1",
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
            "lease_id": "lease-live-1",
            "issuer": BUYER_KERNEL_ID,
            "expires_at_unix_ms": 1800003600000,
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
            "remote_receipt_sha256": "3" * 64,
            "lease_refs": ["lease-live-1"],
            "governance_refs": ["gov-receipt-1"],
            "signer_kernel_ids": [BUYER_KERNEL_ID, VENDOR_B_KERNEL_ID],
        },
    },
}
dsse_payload = json.dumps(dsse_statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
dsse_pae_bytes = dsse_pae("application/vnd.in-toto+json", dsse_payload)
write(
    "bilateral-dsse-envelope.json",
    {
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
    },
)

workflow_receipt = {
    "schema": "chio.workflow-receipt.v2",
    "workflowId": "workflow-live-1",
}
workflow_path = write("workflow-receipt.json", workflow_receipt)
runtime_run_report = {
    "schema": "chio.chiodos.runtime-workflow-run-report.v1",
    "runId": "run-live-1",
}
write("runtime-run-report.json", runtime_run_report)

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
    "bilateralInvocationSha256": "4" * 64,
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
            "expectedCode": "chiodos_buyer_packet_hash_mismatch",
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
    packet["workflowReceiptSha256"] = canonical_hash_file("workflow-receipt.json")
    packet["proofPackageSha256"] = canonical_hash_file("proof-package.json")
    packet["verifierReportSha256"] = canonical_hash_file("verifier-report.json")

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
elif case_id == "missing-co-signature":
    envelope = load("bilateral-dsse-envelope.json")
    envelope["signatures"] = envelope["signatures"][:1]
    write("bilateral-dsse-envelope.json", envelope)
elif case_id == "duplicate-dsse-signature-keyid":
    envelope = load("bilateral-dsse-envelope.json")
    envelope["signatures"][1]["keyid"] = envelope["signatures"][0]["keyid"]
    write("bilateral-dsse-envelope.json", envelope)
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
    packet = load("buyer-attestation-packet.json")
    set_packet_hashes(packet)
    write("buyer-attestation-packet.json", packet)
elif case_id == "verifier-report-rejected":
    report = load("verifier-report.json")
    report["accepted"] = False
    report["failure"] = {
        "code": "package.claim",
        "phase": "package",
        "detail": "negative verifier report rejected"
    }
    write("verifier-report.json", report)
    packet = load("buyer-attestation-packet.json")
    set_packet_hashes(packet)
    write("buyer-attestation-packet.json", packet)
elif case_id == "request-smuggled-trust-root":
    set_dsse_treaty_field("request_sha256", "a" * 64)
elif case_id == "dynamic-trust-claim":
    set_dsse_treaty_field("consistency_model", "dynamic_trust")
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

if [[ "$MODE" == "schema-only" || "$MODE" == "full" ]]; then
  validate_schema "$schema_dir/receipt-lineage-bundle.schema.json" "$tmpdir/run/receipt-lineage-bundle.json"
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
  cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission
  cargo test -p chio-chiodos-runtime receipt_lineage_bundle --test runtime_admission
fi
