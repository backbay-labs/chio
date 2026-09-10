#!/usr/bin/env python3
"""Negative controls for native release dependency parsing and source selection."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LINKAGE = load("check-macos-release-linkage")
PREPARE = load("prepare-macos-release-openssl")


def inventory(path):
    return f"/tmp/chio:\n\t{path} (compatibility version 1.0.0, current version 1.0.0)\n"


class PortabilityTests(unittest.TestCase):
    def test_system_library_dependencies_pass(self):
        for path in ("/usr/lib/libSystem.B.dylib",
                     "/System/Library/Frameworks/Security.framework/Versions/A/Security"):
            with self.subTest(path=path):
                self.assertEqual(LINKAGE.dependencies(inventory(path)), [path])

    def test_non_system_and_unresolved_dependencies_fail(self):
        for path in ("/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
                     "/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib",
                     "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
                     "/opt/local/lib/libssl.dylib", "@rpath/libssl.dylib",
                     "@loader_path/libssl.dylib", "libssl.dylib",
                     "/usr/lib/../../opt/homebrew/libssl.dylib",
                     "/System/LibraryFake/libssl.dylib", "/usr/library/libssl.dylib"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                LINKAGE.dependencies(inventory(path))

    def test_empty_or_malformed_tool_output_fails(self):
        for text in ("", "/tmp/chio:\n", "warning\n", inventory("/usr/lib/libSystem.B.dylib") + "warning\n",
                     "/tmp/chio:\n\t/usr/lib/libSystem.B.dylib\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                LINKAGE.dependencies(text)

    def test_target_specific_static_environment_has_no_discovery_fallback(self):
        for target in PREPARE.TARGETS:
            env = PREPARE.build_environment(target, Path("/tmp/isolated install"))
            key = target.upper().replace("-", "_")
            self.assertEqual(env[f"{key}_OPENSSL_STATIC"], "1")
            self.assertEqual(env[f"{key}_OPENSSL_LIBS"], "ssl:crypto")
            self.assertEqual(env[f"{key}_OPENSSL_LIB_DIR"], "/tmp/isolated install/lib")
            self.assertEqual(env[f"{key}_OPENSSL_INCLUDE_DIR"], "/tmp/isolated install/include")

    def test_bad_source_checksum_refuses_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            archive.write_bytes(b"checksum-negative-control")
            args = ["prepare", "--target", "aarch64-apple-darwin", "--output", str(root / "build"),
                    "--archive", str(archive)]
            with patch.object(sys, "argv", args), patch.object(PREPARE.platform, "system", return_value="Darwin"), \
                    patch.object(PREPARE.platform, "machine", return_value="arm64"), \
                    patch.object(PREPARE.subprocess, "run") as run, self.assertRaisesRegex(ValueError, "checksum"):
                PREPARE.main()
            run.assert_not_called()

    def test_existing_output_is_never_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "operator-state"
            sentinel.write_text("preserve")
            args = ["prepare", "--target", "aarch64-apple-darwin", "--output", directory]
            with patch.object(sys, "argv", args), patch.object(PREPARE.platform, "system", return_value="Darwin"), \
                    patch.object(PREPARE.platform, "machine", return_value="arm64"), \
                    patch.object(PREPARE.subprocess, "run") as run, self.assertRaises(FileExistsError):
                PREPARE.main()
            run.assert_not_called()
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_wrong_native_architecture_refuses_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build"
            args = ["prepare", "--target", "x86_64-apple-darwin", "--output", str(output)]
            with patch.object(sys, "argv", args), patch.object(PREPARE.platform, "system", return_value="Darwin"), \
                    patch.object(PREPARE.platform, "machine", return_value="arm64"), self.assertRaises(ValueError):
                PREPARE.main()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
