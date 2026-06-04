from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from verify_artifacts import ArtifactError, verify_artifact_tree


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_valid_artifacts(root: Path) -> None:
    capability = {
        "schema": "chio.capability.v1",
        "id": "cap-demo",
        "issuer": "issuer",
        "subject": "subject",
        "scope": {
            "grants": [
                {
                    "server_id": "http-sidecar-client",
                    "tool_name": "hello_trust_control_invoke",
                    "operations": ["invoke"],
                }
            ]
        },
        "issued_at": 1,
        "expires_at": 2,
        "signature": "sig",
    }
    write_json(root / "capability.json", {"capability": capability})
    (root / "capability.token").write_text(
        json.dumps(capability, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    write_json(
        root / "status-before.json",
        {
            "capability_id": "cap-demo",
            "revocation_backend": "http://127.0.0.1:8123",
            "revoked": False,
        },
    )
    write_json(
        root / "revoke.json",
        {
            "capability_id": "cap-demo",
            "revocation_backend": "http://127.0.0.1:8123",
            "revoked": True,
            "newly_revoked": True,
        },
    )
    write_json(
        root / "status-after.json",
        {
            "capability_id": "cap-demo",
            "revocation_backend": "http://127.0.0.1:8123",
            "revoked": True,
        },
    )
    write_json(
        root / "check.json",
        {
            "params": {"path": "README.md"},
            "policy_hash": "policy-hash",
            "policy_source_hash": "policy-source-hash",
            "reason": None,
            "receipt_id": "receipt-demo",
            "server": "*",
            "tool": "read_file",
            "verdict": "ALLOW",
        },
    )
    (root / "receipts.ndjson").write_text(
        json.dumps(
            {
                "id": "receipt-demo",
                "tool_server": "*",
                "tool_name": "read_file",
                "decision": {"verdict": "allow"},
                "policy_hash": "policy-hash",
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    evidence = root / "evidence"
    evidence.mkdir()
    write_json(evidence / "manifest.json", {"schema": "demo"})
    (evidence / "receipts.ndjson").write_text("{}\n", encoding="utf-8")
    write_json(
        root / "verify.json",
        {
            "schema": "chio.evidence_export_manifest.v1",
            "toolReceipts": 1,
            "verifiedFiles": 2,
        },
    )


class ArtifactVerifierTests(unittest.TestCase):
    def test_valid_artifacts_write_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifacts(root)

            summary = verify_artifact_tree(root, write_summary=True)

            self.assertEqual(summary["capability_id"], "cap-demo")
            self.assertEqual(summary["receipt_id"], "receipt-demo")
            saved = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(saved, summary)
            self.assertEqual(verify_artifact_tree(root), summary)

    def test_rejects_token_that_does_not_match_issued_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifacts(root)
            (root / "capability.token").write_text('{"id":"wrong"}\n', encoding="utf-8")

            with self.assertRaisesRegex(ArtifactError, "capability.token"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_revocation_status_for_different_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifacts(root)
            status = json.loads((root / "status-after.json").read_text(encoding="utf-8"))
            status["capability_id"] = "cap-other"
            write_json(root / "status-after.json", status)

            with self.assertRaisesRegex(ArtifactError, "status-after.json"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_receipt_list_missing_check_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifacts(root)
            (root / "receipts.ndjson").write_text(
                json.dumps({"id": "other-receipt"}) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ArtifactError, "receipts.ndjson"):
                verify_artifact_tree(root, write_summary=True)

    def test_rejects_summary_that_does_not_match_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_artifacts(root)
            verify_artifact_tree(root, write_summary=True)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["receipt_id"] = "other-receipt"
            write_json(root / "summary.json", summary)

            with self.assertRaisesRegex(ArtifactError, "summary.json.receipt_id"):
                verify_artifact_tree(root)


if __name__ == "__main__":
    unittest.main()
