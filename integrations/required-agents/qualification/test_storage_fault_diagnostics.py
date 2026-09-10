"""Private diagnostic regression tests; no host, Docker or kernel is launched."""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "storage_fault", Path(__file__).with_name("storage_fault.py"))
storage_fault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage_fault)


class SubprocessDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "fresh-owner"
        self.diagnostics = storage_fault.diagnostic_directory(self.state)

    def run_child(self, source, *arguments, timeout=5):
        return storage_fault.run(
            [sys.executable, "-c", source, *arguments], timeout=timeout,
            diagnostic_dir=self.diagnostics, operation="fixture-child")

    def assert_private_evidence(self, summary):
        self.assertEqual(self.diagnostics.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(self.diagnostics.stat().st_mode), 0o700)
        self.assertFalse(self.state.exists())
        for name in ["stdout", "stderr"]:
            path = Path(summary[name]["path"])
            self.assertTrue(path.is_relative_to(self.diagnostics))
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(summary[name]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(summary[name]["bytes"], path.stat().st_size)
        record = path.parent / "failure.json"
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual(json.loads(record.read_text()), summary)

    def test_nonzero_preserves_exact_bytes_and_hides_argv_and_output(self):
        secret = "fixture-secret-not-for-public-errors"
        with self.assertRaises(RuntimeError) as failure:
            self.run_child("import os,sys;os.write(1,b'out\\xff');"
                           "os.write(2,sys.argv[1].encode()+b'\\x00\\xfe');sys.exit(7)", secret)
        summary = failure.exception.diagnostics
        self.assertEqual(failure.exception.returncode, 7)
        self.assertEqual(summary["returncode"], 7)
        self.assertEqual(Path(summary["stdout"]["path"]).read_bytes(), b"out\xff")
        self.assertEqual(Path(summary["stderr"]["path"]).read_bytes(), secret.encode() + b"\x00\xfe")
        self.assertNotIn(secret, str(failure.exception))
        self.assertNotIn("sys.argv", str(failure.exception))
        self.assert_private_evidence(summary)

    def test_timeout_preserves_partial_bytes_and_does_not_retry(self):
        marker = self.root / "launches.txt"
        secret = "timeout-private-fixture"
        source = ("import os,sys,time;"
                  "open(sys.argv[1],'a').write('launched\\n');"
                  "os.write(1,b'partial\\xff');os.write(2,sys.argv[2].encode());time.sleep(10)")
        with self.assertRaises(subprocess.TimeoutExpired) as failure:
            self.run_child(source, str(marker), secret, timeout=0.5)
        summary = failure.exception.diagnostics
        self.assertEqual(summary["status"], "timeout")
        self.assertEqual(summary["timeoutSeconds"], 0.5)
        self.assertEqual(Path(summary["stdout"]["path"]).read_bytes(), b"partial\xff")
        self.assertEqual(Path(summary["stderr"]["path"]).read_bytes(), secret.encode())
        self.assertIsNone(failure.exception.output)
        self.assertIsNone(failure.exception.stderr)
        self.assertNotIn(secret, str(failure.exception))
        self.assertEqual(marker.read_text(), "launched\n")
        self.assert_private_evidence(summary)

    def test_success_retains_text_return_and_universal_newlines(self):
        self.assertEqual(self.run_child("import os;os.write(1,b'one\\r\\ntwo\\r')"), "one\ntwo\n")
        self.assertEqual(list(self.diagnostics.iterdir()), [])

    def test_existing_public_directory_rejected_before_launch(self):
        self.diagnostics.mkdir(mode=0o755)
        self.diagnostics.chmod(0o755)
        with patch.object(storage_fault.subprocess, "run") as child:
            with self.assertRaises(PermissionError):
                self.run_child("raise SystemExit(0)")
            child.assert_not_called()

    def test_symlink_directory_rejected_before_launch(self):
        self.diagnostics.symlink_to(self.root, target_is_directory=True)
        with patch.object(storage_fault.subprocess, "run") as child:
            with self.assertRaises(PermissionError):
                self.run_child("raise SystemExit(0)")
            child.assert_not_called()

    def test_wrong_owner_rejected_before_launch(self):
        self.diagnostics.mkdir(mode=0o700)
        with patch.object(storage_fault.os, "geteuid", return_value=os.geteuid() + 1):
            with patch.object(storage_fault.subprocess, "run") as child:
                with self.assertRaises(PermissionError):
                    self.run_child("raise SystemExit(0)")
                child.assert_not_called()

    def test_failure_records_are_unique_and_preserve_previous_attempt(self):
        paths = []
        for text in ["first", "second"]:
            with self.assertRaises(RuntimeError) as failure:
                self.run_child("import sys;print(sys.argv[1]);sys.exit(9)", text)
            paths.append(Path(failure.exception.diagnostics["stdout"]["path"]))
        self.assertNotEqual(*paths)
        self.assertEqual([path.read_text() for path in paths], ["first\n", "second\n"])

    def test_diagnostic_storage_error_preserves_child_failure_status(self):
        with patch.object(storage_fault.tempfile, "mkdtemp", side_effect=OSError(errno.ENOSPC, "private message")):
            with self.assertRaises(RuntimeError) as failure:
                self.run_child("raise SystemExit(23)")
        self.assertEqual(failure.exception.returncode, 23)
        self.assertEqual(failure.exception.diagnostics["diagnosticStorageError"]["errno"], errno.ENOSPC)
        self.assertNotIn("private message", str(failure.exception))

    def test_launch_error_type_is_retained_without_executable_disclosure(self):
        with self.assertRaises(FileNotFoundError) as failure:
            storage_fault.run([str(self.root / "private-command-missing")],
                              diagnostic_dir=self.diagnostics, operation="fixture-launch")
        self.assertEqual(failure.exception.errno, errno.ENOENT)
        self.assertNotIn("private-command-missing", str(failure.exception))
        self.assert_private_evidence(failure.exception.diagnostics)

    def test_timeout_storage_error_preserves_timeout_status(self):
        with patch.object(storage_fault.tempfile, "mkdtemp", side_effect=OSError(errno.ENOSPC, "private message")):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                self.run_child("import time;time.sleep(10)", timeout=0.1)
        self.assertEqual(failure.exception.diagnostics["status"], "timeout")
        self.assertEqual(failure.exception.diagnostics["diagnosticStorageError"]["errno"], errno.ENOSPC)
        self.assertNotIn("private message", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
