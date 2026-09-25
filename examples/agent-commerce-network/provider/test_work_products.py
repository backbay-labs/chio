"""Retained work cannot be substituted or billed again under a reused job ID."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from review import execute_review, open_dispute


class WorkProductTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.workspace = self.root / "workspace"
        (self.workspace / "service").mkdir(parents=True)
        (self.workspace / "service/main.py").write_text("result = eval(user_input)\n")
        self.environment = patch.dict(
            os.environ,
            {
                "PROVIDER_WORKSPACE": str(self.workspace),
                "PROVIDER_ARTIFACTS": str(self.root / "artifacts"),
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.arguments = {
            "job_id": "job_owned",
            "quote_id": "quote_owned",
            "service_family": "security-review",
            "requested_scope": "hotfix-review",
            "target": "service",
        }

    def test_repeated_work_retains_identity_and_dispute(self):
        first = execute_review(self.arguments)
        self.assertEqual(first, execute_review(self.arguments))
        self.assertEqual(first["severity_summary"]["high"], 1)
        args = {
            "job_id": self.arguments["job_id"],
            "reason_code": "quality",
            "summary": "Request further investigation",
        }
        opened = open_dispute(args)
        self.assertEqual(opened, open_dispute(args))
        self.assertEqual(opened["settlement_status"], "reversal_pending")
        with self.assertRaisesRegex(ValueError, "different terms"):
            open_dispute({**args, "reason_code": "other"})

    def test_changed_source_or_retained_work_is_refused(self):
        execute_review(self.arguments)
        source = self.workspace / "service/main.py"
        original = source.read_text()
        source.write_text('print("changed")\n')
        with self.assertRaisesRegex(ValueError, "different source"):
            execute_review(self.arguments)
        source.write_text(original)
        (self.root / "artifacts/job_owned/findings.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "artifact has changed"):
            execute_review(self.arguments)

    def test_traversal_symlink_and_oversized_input_refused(self):
        with self.assertRaises(ValueError):
            execute_review({**self.arguments, "target": "../"})
        (self.workspace / "service/link.py").symlink_to(self.workspace / "service/main.py")
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            execute_review(self.arguments)
        (self.workspace / "service/link.py").unlink()
        (self.workspace / "service/main.py").write_bytes(b"#" * 200001)
        with self.assertRaisesRegex(ValueError, "byte limit"):
            execute_review(self.arguments)

    def test_dispute_requires_retained_fulfillment(self):
        with self.assertRaisesRegex(ValueError, "no retained fulfillment"):
            open_dispute({"job_id": "unknown", "reason_code": "quality", "summary": "Missing work"})
