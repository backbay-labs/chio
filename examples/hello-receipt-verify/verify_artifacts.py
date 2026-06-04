from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


class ArtifactError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ArtifactError(f"missing artifact: {path}") from error
    except json.JSONDecodeError as error:
        raise ArtifactError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ArtifactError(f"{path} must contain a JSON object")
    return payload


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise ArtifactError(f"missing artifact: {path}") from error

    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise ArtifactError(f"invalid JSON in {path}:{index}: {error}") from error
        if not isinstance(payload, dict):
            raise ArtifactError(f"{path}:{index} must contain a JSON object")
        records.append(payload)
    return records


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


def require_object(payload: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ArtifactError(f"{label}.{key} must be an object")
    return value


def require_string(payload: dict[str, Any], key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ArtifactError(f"{label}.{key} must be a non-empty string")
    return value


def sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_file_path(package_dir: Path, relative_path: str) -> Path:
    path = Path(relative_path)
    require(
        not path.is_absolute() and ".." not in path.parts,
        f"manifest path is not package-local: {relative_path}",
    )
    return package_dir / path


def validate_manifest_files(package_dir: Path, manifest: dict[str, Any]) -> int:
    files = manifest.get("files")
    require(isinstance(files, list), "manifest.files must be a list")
    seen: set[str] = set()
    for index, entry in enumerate(files, start=1):
        require(isinstance(entry, dict), f"manifest.files[{index}] must be an object")
        relative_path = require_string(entry, "path", f"manifest.files[{index}]")
        require(relative_path not in seen, f"duplicate manifest path: {relative_path}")
        seen.add(relative_path)
        file_path = package_file_path(package_dir, relative_path)
        require(file_path.is_file(), f"manifest file is missing: {relative_path}")
        data = file_path.read_bytes()
        require(
            entry.get("bytes") == len(data),
            f"manifest byte count mismatch for {relative_path}",
        )
        require(
            entry.get("sha256") == sha256_hex(file_path),
            f"manifest hash mismatch for {relative_path}",
        )
    return len(files)


def validate_record_count(manifest: dict[str, Any], key: str, actual: int) -> None:
    counts = require_object(manifest, "counts", "manifest")
    require(counts.get(key) == actual, f"manifest counts.{key} must be {actual}")


def validate_receipt_semantics(manifest: dict[str, Any]) -> None:
    semantics = require_object(manifest, "receiptSemantics", "manifest")
    expected = {
        "mediatedDecisions": 1,
        "traceObservations": 0,
        "advisoryEvaluations": 0,
        "prevent": 1,
        "detectOnly": 0,
        "advisoryOnly": 0,
        "cannotSee": 0,
        "authorized": 1,
    }
    for key, value in expected.items():
        require(semantics.get(key) == value, f"manifest receiptSemantics.{key} drifted")


def validate_package(package_dir: Path) -> dict[str, Any]:
    manifest = load_json(package_dir / "manifest.json")
    require(
        manifest.get("schema") == "chio.evidence_export_manifest.v1",
        "manifest schema drifted",
    )
    file_count = validate_manifest_files(package_dir, manifest)
    require(file_count >= 8, "minimal evidence package must cover all fixture files")

    query = load_json(package_dir / "query.json")
    require(manifest.get("query") == query, "manifest query must match query.json")
    read_boundary = require_object(query, "readBoundary", "query.json")
    require(
        read_boundary.get("kind") == "admin_all",
        "fixture must preserve explicit admin_all read boundary",
    )

    receipts = load_ndjson(package_dir / "receipts.ndjson")
    child_receipts = load_ndjson(package_dir / "child-receipts.ndjson")
    checkpoints = load_ndjson(package_dir / "checkpoints.ndjson")
    lineage = load_ndjson(package_dir / "capability-lineage.ndjson")
    inclusion_proofs = load_ndjson(package_dir / "inclusion-proofs.ndjson")

    validate_record_count(manifest, "toolReceipts", len(receipts))
    validate_record_count(manifest, "childReceipts", len(child_receipts))
    validate_record_count(manifest, "checkpoints", len(checkpoints))
    validate_record_count(manifest, "capabilityLineage", len(lineage))
    validate_record_count(manifest, "inclusionProofs", len(inclusion_proofs))
    require(len(receipts) == 1, "fixture must carry exactly one tool receipt")
    require(len(lineage) == 1, "fixture must carry exactly one lineage record")
    require(not child_receipts, "fixture child receipts must stay empty")
    require(not checkpoints, "fixture checkpoints must stay empty")
    require(not inclusion_proofs, "fixture inclusion proofs must stay empty")

    proof_coverage = require_object(manifest, "proofCoverage", "manifest")
    require(proof_coverage.get("checkpointedReceipts") == 0, "checkpointed count drifted")
    require(proof_coverage.get("uncheckpointedReceipts") == 1, "uncheckpointed count drifted")
    validate_receipt_semantics(manifest)

    receipt_wrapper = receipts[0]
    receipt = require_object(receipt_wrapper, "receipt", "receipts.ndjson")
    lineage_record = lineage[0]
    receipt_id = require_string(receipt, "id", "receipt")
    capability_id = require_string(receipt, "capability_id", "receipt")
    require(receipt.get("tool_name") == "read_file", "receipt tool_name drifted")
    require(receipt.get("tool_server") == "*", "receipt tool_server drifted")
    require(receipt.get("receipt_kind") == "mediated_decision", "receipt kind drifted")
    require(receipt.get("boundary_class") == "prevent", "receipt boundary class drifted")
    decision = require_object(receipt, "decision", "receipt")
    require(decision.get("verdict") == "allow", "receipt verdict drifted")

    require(
        lineage_record.get("capability_id") == capability_id,
        "lineage capability_id must match receipt capability_id",
    )
    require(lineage_record.get("delegation_depth") == 0, "lineage delegation depth drifted")
    grants_json = require_string(lineage_record, "grants_json", "lineage")
    try:
        grants = json.loads(grants_json)
    except json.JSONDecodeError as error:
        raise ArtifactError(f"lineage grants_json is invalid JSON: {error}") from error
    require(
        grants == {
            "grants": [
                {
                    "server_id": "*",
                    "tool_name": "read_file",
                    "operations": ["invoke"],
                }
            ]
        },
        "lineage grants_json drifted",
    )

    attribution = require_object(
        require_object(receipt, "metadata", "receipt"),
        "attribution",
        "receipt.metadata",
    )
    subject_key = require_string(lineage_record, "subject_key", "lineage")
    issuer_key = require_string(lineage_record, "issuer_key", "lineage")
    require(attribution.get("subject_key") == subject_key, "receipt subject attribution drifted")
    require(attribution.get("issuer_key") == issuer_key, "receipt issuer attribution drifted")

    return {
        "example": "hello-receipt-verify",
        "receipt_id": receipt_id,
        "capability_id": capability_id,
        "tool_name": "read_file",
        "subject_key": subject_key,
        "issuer_key": issuer_key,
        "read_boundary": "admin_all",
        "verified": True,
    }


def validate_verify_output(root: Path, manifest_file_count: int) -> None:
    verify = load_json(root / "verify.json")
    require(
        verify.get("schema") == "chio.evidence_export_manifest.v1",
        "verify.json schema drifted",
    )
    require(verify.get("toolReceipts") == 1, "verify.json toolReceipts drifted")
    require(verify.get("capabilityLineage") == 1, "verify.json capabilityLineage drifted")
    require(verify.get("uncheckpointedReceipts") == 1, "verify.json uncheckpointedReceipts drifted")
    require(verify.get("childReceipts") == 0, "verify.json childReceipts drifted")
    require(verify.get("checkpoints") == 0, "verify.json checkpoints drifted")
    require(verify.get("inclusionProofs") == 0, "verify.json inclusionProofs drifted")
    require(verify.get("verifiedFiles") == manifest_file_count, "verify.json verifiedFiles drifted")
    require(verify.get("childReceiptScope") == "full_query_window", "child receipt scope drifted")
    validate_receipt_semantics(verify)
    claim_boundary = require_object(verify, "claimBoundary", "verify.json")
    require(
        claim_boundary.get("schema") == "chio.evidence_transparency_claims.v1",
        "claim boundary schema drifted",
    )


def validate_tamper_error(root: Path) -> None:
    stdout = root / "tamper-out.json"
    if stdout.exists():
        require(stdout.read_text(encoding="utf-8").strip() == "", "tamper stdout must be empty")
    payload = load_json(root / "tamper-err.json")
    require(
        payload.get("code") == "urn:chio:error:attest:provenance-missing",
        "tamper error code drifted",
    )
    message = require_string(payload, "message", "tamper-err.json")
    require("hash mismatch" in message and "query.json" in message, "tamper error message drifted")
    context = require_object(payload, "context", "tamper-err.json")
    require(context.get("domain") == "attest", "tamper error domain drifted")
    require(context.get("severity") == "error", "tamper error severity drifted")
    require(
        context.get("string_code") == "CHIO-ATTEST-PROVENANCE-MISSING",
        "tamper error string_code drifted",
    )


def validate_or_write_summary(root: Path, summary: dict[str, Any], write: bool) -> None:
    path = root / "summary.json"
    if write:
        path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return
    existing = load_json(path)
    for key, value in summary.items():
        require(existing.get(key) == value, f"summary.json.{key} drifted")


def verify_artifact_tree(root: Path, *, write_summary: bool = False) -> dict[str, Any]:
    package_dir = root / "input-package"
    summary = validate_package(package_dir)
    manifest = load_json(package_dir / "manifest.json")
    validate_verify_output(root, len(manifest["files"]))
    validate_tamper_error(root)
    validate_or_write_summary(root, summary, write_summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--write-summary", action="store_true")
    args = parser.parse_args()

    try:
        summary = verify_artifact_tree(
            args.artifact_root.resolve(), write_summary=args.write_summary
        )
    except ArtifactError as error:
        parser.exit(1, f"artifact verification failed: {error}\n")

    print(json.dumps({"verified": True, **summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
