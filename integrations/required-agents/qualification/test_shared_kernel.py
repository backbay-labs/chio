"""Qualification reporting controls; these do not establish host acceptance."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import shared_kernel


class ResourceSelectionTests(unittest.TestCase):
    def test_direct_server_image_is_rejected_before_execution(self):
        config = {"Entrypoint": ["node", "/opt/resource/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/workspace"]}
        with patch.object(shared_kernel, "run", return_value=json.dumps(config)) as run:
            with self.assertRaisesRegex(ValueError, "independent dispatch audit wrapper"):
                shared_kernel.validate_resource_image("sha256:test")
        self.assertEqual(run.call_count, 1)

    def test_changed_observer_is_rejected(self):
        config = {"Entrypoint": ["node", "/opt/resource/audit-tool-server.mjs"]}
        with patch.object(shared_kernel, "run", side_effect=[json.dumps(config), "0" * 64]):
            with self.assertRaisesRegex(ValueError, "differs from the selected source"):
                shared_kernel.validate_resource_image("sha256:test")

    def test_matching_observer_identity_is_retained(self):
        config = {"Entrypoint": ["node", "/opt/resource/audit-tool-server.mjs"]}
        source = Path(shared_kernel.__file__).parent.parent / "filesystem" / "audit-tool-server.mjs"
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with patch.object(shared_kernel, "run", side_effect=[json.dumps(config), digest]):
            result = shared_kernel.validate_resource_image("sha256:test")
        self.assertEqual(result, {"entrypoint": config["Entrypoint"], "auditWrapperSha256": digest})


class ObservationFailureTests(unittest.TestCase):
    def test_unexpected_dispatch_preserves_failure_state(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = shared_kernel.Runtime.__new__(shared_kernel.Runtime)
            runtime.directory = Path(directory) / "bounded-approval-workflow"
            runtime.directory.mkdir()
            runtime.volume, runtime.audit_volume, runtime.image = "owned-resource", "owned-audit", "sha256:test"
            runtime.remaining_volumes = [runtime.volume, runtime.audit_volume]
            runtime.preserve_volumes = False
            runtime.evidence = []
            runtime.log = io.StringIO()
            runtime.stop = Mock()
            audit = json.dumps({"tool": "write_file", "path": "/workspace/forbidden.txt"})
            with patch.object(shared_kernel, "run", side_effect=["", audit]):
                with self.assertRaisesRegex(AssertionError, "observed.*forbidden.txt"):
                    runtime.finish()
            self.assertTrue(runtime.preserve_volumes)
            raw = json.loads((runtime.directory / "raw.json").read_text())
            self.assertEqual(raw[-1]["retainedVolumes"], [runtime.volume, runtime.audit_volume])
            self.assertEqual((runtime.directory / "resource-dispatch.jsonl").read_text(), audit + "\n")

    def test_cleanup_failure_cannot_leave_passed_manifest_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "chio"
            binary.write_bytes(b"test binary identity only")
            output = Path(directory) / "output"
            runtime = Mock()
            runtime.finish.side_effect = AssertionError("independent resource dispatch differs")
            arguments = ["shared_kernel.py", "--binary", str(binary), "--output", str(output), "--cases", "authority-replay"]
            with patch.object(shared_kernel.sys, "argv", arguments), \
                    patch.object(shared_kernel, "run", return_value="test metadata"), \
                    patch.object(shared_kernel, "validate_resource_image", return_value={}), \
                    patch.object(shared_kernel, "Runtime", return_value=runtime), \
                    patch.object(shared_kernel, "basic_cases"), contextlib.redirect_stdout(io.StringIO()):
                code = shared_kernel.main()
            self.assertEqual(code, 1)
            result = json.loads((output / "manifest.json").read_text())["cases"][0]
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["cleanupError"], "independent resource dispatch differs")


if __name__ == "__main__":
    unittest.main()
