#!/usr/bin/env python3
"""Negative controls for native release dependency parsing and source selection."""
import importlib.util
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
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
SCAN = load("scan-macos-release-openssl")


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


class NativeScanTests(unittest.TestCase):
    def setUp(self):
        # Synthetic report fixtures exercise refusal rules only. They are never
        # promoted to scanner output or accepted native build evidence.
        self.binary = Path("/tmp/isolated/install/bin/openssl")
        self.sha = "a" * 64
        self.now = datetime(2026, 9, 10, tzinfo=timezone.utc)
        self.catalog = {"bomFormat": "CycloneDX", "components": [
            {"name": "openssl", "type": "application", "version": "3.6.4",
             "purl": "pkg:generic/openssl@3.6.4", "cpe": "cpe:2.3:a:openssl:openssl:3.6.4:*:*:*:*:*:*:*",
             "properties": [{"name": "syft:package:foundBy", "value": "binary-classifier-cataloger"}]},
            {"type": "file", "name": str(self.binary), "hashes": [{"alg": "SHA-256", "content": self.sha}]},
        ]}
        self.report = {"source": {"type": "file", "target": str(self.binary)}, "matches": [],
                       "ignoredMatches": [], "descriptor": {"name": "grype", "version": "0.118.0",
                       "configuration": {"ignore": [], "exclude": [], "vex-documents": [], "vex-add": [],
                                         "only-fixed": False, "only-notfixed": False, "ignore-wontfix": "",
                                         "match": {"stock": {"using-cpes": True}}},
                       "db": {"status": {"built": "2026-09-09T06:31:00Z", "valid": True}}}}

    def validate(self, catalog=None, report=None):
        SCAN.validate_reports(catalog or self.catalog, report or self.report, self.binary, self.sha, self.now)

    def test_bound_unfiltered_fresh_report_structure_passes(self):
        self.validate()

    def test_undiscovered_or_wrong_native_component_refuses(self):
        for field, value in (("version", "3.6.3"), ("purl", "pkg:generic/other@3.6.4"),
                             ("properties", []), ("type", "library")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                catalog = deepcopy(self.catalog)
                catalog["components"][0][field] = value
                self.validate(catalog=catalog)

    def test_substituted_binary_refuses(self):
        catalog = deepcopy(self.catalog)
        catalog["components"][1]["hashes"][0]["content"] = "b" * 64
        with self.assertRaises(ValueError):
            self.validate(catalog=catalog)
        report = deepcopy(self.report)
        report["source"]["target"] = "/tmp/another-openssl"
        with self.assertRaises(ValueError):
            self.validate(report=report)

    def test_prepared_library_tampering_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = Path(directory)
            contents = {"lib/libssl.a": b"static-test-ssl", "lib/libcrypto.a": b"static-test-crypto",
                        "include/openssl/header.h": b"test-header"}
            for name, data in contents.items():
                path = prepared / "install" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (prepared / "commands.json").write_text("[]\n")
            license_path = prepared / "source/openssl-3.6.4/LICENSE.txt"
            license_path.parent.mkdir(parents=True)
            license_path.write_text("test-license\n")
            manifest = {"name": "openssl", "version": "3.6.4", "target": "aarch64-apple-darwin",
                        "source_url": PREPARE.SOURCE_URL, "source_sha256": PREPARE.SOURCE_SHA256,
                        "test_command_exit": 0, "files": {name: SCAN.digest(prepared / "install" / name) for name in contents},
                        "commands_sha256": SCAN.digest(prepared / "commands.json"),
                        "license_sha256": SCAN.digest(license_path), "recipe_sha256": SCAN.digest(Path(PREPARE.__file__))}
            (prepared / "native-openssl.json").write_text(json.dumps(manifest))
            self.assertEqual(SCAN.prepared_identity(prepared, "aarch64-apple-darwin"), manifest)
            (prepared / "install/lib/libcrypto.a").write_bytes(b"substituted")
            with self.assertRaisesRegex(ValueError, "file identity"):
                SCAN.prepared_identity(prepared, "aarch64-apple-darwin")

    def test_wrong_native_source_refuses_before_file_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = Path(directory)
            (prepared / "native-openssl.json").write_text(json.dumps({
                "name": "openssl", "version": "3.6.4", "target": "aarch64-apple-darwin",
                "source_url": PREPARE.SOURCE_URL, "source_sha256": "0" * 64, "test_command_exit": 0,
            }))
            with self.assertRaisesRegex(ValueError, "preparation identity"):
                SCAN.prepared_identity(prepared, "aarch64-apple-darwin")

    def test_findings_or_ignored_findings_refuse(self):
        for field in ("matches", "ignoredMatches"):
            report = deepcopy(self.report)
            report[field] = [{"id": "test-finding"}]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(report=report)

    def test_scan_filters_refuse_even_without_reported_findings(self):
        for field, value in (("ignore", [{}]), ("exclude", ["*"]), ("vex-documents", ["vex.json"]),
                             ("vex-add", ["not_affected"]), ("only-fixed", True), ("only-notfixed", True),
                             ("ignore-wontfix", "unknown")):
            report = deepcopy(self.report)
            report["descriptor"]["configuration"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(report=report)

    def test_disabled_matching_or_wrong_scanner_refuses(self):
        report = deepcopy(self.report)
        report["descriptor"]["configuration"]["match"]["stock"]["using-cpes"] = False
        with self.assertRaises(ValueError):
            self.validate(report=report)
        report = deepcopy(self.report)
        report["descriptor"]["version"] = "0.0.0"
        with self.assertRaises(ValueError):
            self.validate(report=report)

    def test_stale_future_or_invalid_database_refuses(self):
        for age in (timedelta(days=6), timedelta(hours=-1)):
            report = deepcopy(self.report)
            report["descriptor"]["db"]["status"]["built"] = (self.now - age).isoformat()
            with self.subTest(age=age), self.assertRaises(ValueError):
                self.validate(report=report)
        report = deepcopy(self.report)
        report["descriptor"]["db"]["status"]["valid"] = False
        with self.assertRaises(ValueError):
            self.validate(report=report)


if __name__ == "__main__":
    unittest.main()
