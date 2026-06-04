from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_artifacts import ArtifactError, verify_artifact_tree


EXAMPLE_ROOT = Path(__file__).resolve().parent
FIXTURE_ROOT = EXAMPLE_ROOT / "fixtures" / "minimal-evidence"


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_manifest_entry(package_dir: Path, relative_path: str) -> None:
    manifest_path = package_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = package_dir / relative_path
    for entry in manifest["files"]:
        if entry["path"] == relative_path:
            entry["bytes"] = len(target.read_bytes())
            entry["sha256"] = file_sha256(target)
            write_json(manifest_path, manifest)
            return
    raise AssertionError(f"missing manifest entry for {relative_path}")


def write_valid_verify_output(root: Path) -> None:
    manifest = json.loads((root / "input-package" / "manifest.json").read_text(encoding="utf-8"))
    write_json(
        root / "verify.json",
        {
            "schema": "chio.evidence_export_manifest.v1",
            "verifiedAt": 1,
            "toolReceipts": 1,
            "childReceipts": 0,
            "checkpoints": 0,
            "checkpointPublications": 0,
            "checkpointWitnesses": 0,
            "checkpointConsistencyProofs": 0,
            "checkpointEquivocations": 0,
            "capabilityLineage": 1,
            "inclusionProofs": 0,
            "uncheckpointedReceipts": 1,
            "receiptSemantics": manifest["receiptSemantics"],
            "verifiedFiles": len(manifest["files"]),
            "childReceiptScope": "full_query_window",
            "claimBoundary": {
                "schema": "chio.evidence_transparency_claims.v1",
                "publicationState": "transparency_preview",
                "audit": {"capabilityLineageRecords": 1},
            },
        },
    )


def write_valid_tamper_error(root: Path) -> None:
    (root / "tamper-out.json").write_text("", encoding="utf-8")
    write_json(
        root / "tamper-err.json",
        {
            "code": "urn:chio:error:attest:provenance-missing",
            "message": "evidence package file hash mismatch for query.json",
            "context": {
                "domain": "attest",
                "severity": "error",
                "stability": "unstable",
                "string_code": "CHIO-ATTEST-PROVENANCE-MISSING",
            },
            "suggested_fix": (
                "Regenerate the evidence bundle and include provenance before "
                "submitting the operation."
            ),
        },
    )


def write_valid_artifact_root(root: Path) -> None:
    shutil.copytree(FIXTURE_ROOT, root / "input-package")
    write_valid_verify_output(root)
    write_valid_tamper_error(root)


class ReceiptVerifyArtifactTests(unittest.TestCase):
    def test_valid_fixture_writes_and_revalidates_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifact_root(root)

            summary = verify_artifact_tree(root, write_summary=True)

            self.assertEqual(summary["example"], "hello-receipt-verify")
            self.assertEqual(summary["tool_name"], "read_file")
            self.assertEqual(summary["read_boundary"], "admin_all")
            saved = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(saved, summary)
            self.assertEqual(verify_artifact_tree(root), summary)

    def test_rejects_manifest_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifact_root(root)
            query_path = root / "input-package" / "query.json"
            query_path.write_text(
                query_path.read_text(encoding="utf-8").replace("admin_all", "admin_xll"),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ArtifactError, "manifest hash mismatch"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_receipt_lineage_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifact_root(root)
            lineage_path = root / "input-package" / "capability-lineage.ndjson"
            lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
            lineage["capability_id"] = "cap-other"
            lineage_path.write_text(
                json.dumps(lineage, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            refresh_manifest_entry(root / "input-package", "capability-lineage.ndjson")

            with self.assertRaisesRegex(ArtifactError, "lineage capability_id"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_old_tamper_error_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifact_root(root)
            payload = json.loads((root / "tamper-err.json").read_text(encoding="utf-8"))
            payload["context"].pop("string_code")
            payload["context"]["legacy_string_code"] = "CHIO-ATTEST-PROVENANCE-MISSING"
            write_json(root / "tamper-err.json", payload)

            with self.assertRaisesRegex(ArtifactError, "string_code"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_summary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifact_root(root)
            verify_artifact_tree(root, write_summary=True)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["receipt_id"] = "other-receipt"
            write_json(root / "summary.json", summary)

            with self.assertRaisesRegex(ArtifactError, "summary.json.receipt_id"):
                verify_artifact_tree(root)


if __name__ == "__main__":
    unittest.main()
