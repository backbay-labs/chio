#!/usr/bin/env python3
"""Mutation controls for the executable inventory gate, not host acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check-release-binary-sbom.py"
SPEC = importlib.util.spec_from_file_location("binary_sbom_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
VERSION = "0.1.1-rc.1"


class BinaryInventoryGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chio-sbom-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "chio"
        self.binary.write_bytes(b"synthetic executable identity fixture")
        cli = self.root / GATE.CLI_MANIFEST
        cli.parent.mkdir(parents=True)
        cli.write_text('[package]\nname="chio-cli"\nversion="' + VERSION + '"\n'
                       '[dependencies]\n' + ''.join(
                           f'{name}={{workspace=true}}\n' for name in GATE.CRITICAL))
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion="0.1.0"\n[workspace.dependencies]\n' + ''.join(
                f'{name}={{path="crates/{name}"}}\n' for name in GATE.CRITICAL))
        packages = [("chio-cli", VERSION)] + [(name, "0.1.0") for name in GATE.CRITICAL]
        # A lock-only build/other-target package is deliberately absent from the binary inventory.
        (self.root / "Cargo.lock").write_text('version=4\n' + ''.join(
            f'[[package]]\nname="{name}"\nversion="{version}"\n'
            for name, version in packages + [("unused-build-fixture", "1.0.0")]))
        for name in GATE.CRITICAL:
            path = self.root / "crates" / name
            path.mkdir()
            (path / "Cargo.toml").write_text(
                f'[package]\nname="{name}"\nversion.workspace=true\n')
        components = []
        for name, version in packages:
            components.append({"type": "library", "bom-ref": "ref-" + name,
                               "name": name, "version": version,
                               "purl": f"pkg:cargo/{name}@{version}",
                               "properties": [
                                   {"name": "syft:package:foundBy", "value": GATE.CATALOGER},
                                   {"name": "syft:package:language", "value": "rust"},
                                   {"name": "syft:package:type", "value": "rust-crate"}]})
        self.document = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                         "metadata": {"component": {"type": "file", "bom-ref": "binary",
                                                     "version": "sha256:" + GATE.digest(self.binary)},
                                      "tools": {"components": [{"name": "syft", "version": "1.51.1"}]}},
                         "components": components,
                         "dependencies": [{"ref": "ref-chio-cli", "dependsOn": [
                             "ref-" + name for name in GATE.CRITICAL]}]}

    def validate(self, document=None):
        return GATE.validate(self.document if document is None else document,
                             self.binary, self.root, VERSION)

    def test_runtime_inventory_accepts_without_unrelated_lock_entries(self):
        result = self.validate()
        self.assertTrue(result["passed"])
        self.assertEqual(result["binarySha256"], GATE.digest(self.binary))
        self.assertEqual(result["rustComponents"], 5)

    def test_empty_inventory_fails_even_with_valid_format(self):
        for value in [None, [], {}]:
            with self.subTest(value=value):
                document = copy.deepcopy(self.document)
                document["components"] = value
                with self.assertRaisesRegex(ValueError, "inventory is empty"):
                    self.validate(document)

    def test_file_and_expected_version_binding(self):
        for value in ["sha256:" + "0" * 64, None, "directory"]:
            with self.subTest(value=value):
                document = copy.deepcopy(self.document)
                document["metadata"]["component"]["version"] = value
                with self.assertRaisesRegex(ValueError, "SHA256"):
                    self.validate(document)
        self.document["metadata"]["component"]["type"] = "application"
        with self.assertRaisesRegex(ValueError, "file scan"):
            self.validate()

    def test_changed_executable_rejects_previous_inventory(self):
        self.binary.write_bytes(b"different synthetic executable")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.validate()

    def test_source_tree_or_wrong_cataloger_cannot_substitute(self):
        for name, value in [("syft:package:foundBy", "rust-cargo-lock-cataloger"),
                            ("syft:package:language", "python"),
                            ("syft:package:type", "python")]:
            with self.subTest(name=name):
                document = copy.deepcopy(self.document)
                for prop in document["components"][0]["properties"]:
                    if prop["name"] == name:
                        prop["value"] = value
                with self.assertRaises(ValueError):
                    self.validate(document)

    def test_critical_inventory_missing_wrong_or_duplicated(self):
        for index in range(len(self.document["components"])):
            with self.subTest(index=index):
                document = copy.deepcopy(self.document)
                del document["components"][index]
                with self.assertRaisesRegex(ValueError, "required binary package"):
                    self.validate(document)
        document = copy.deepcopy(self.document)
        duplicate = copy.deepcopy(document["components"][0])
        duplicate["bom-ref"] = "duplicate-cli"
        document["components"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "required binary package"):
            self.validate(document)

    def test_wrong_identity_version_purl_or_unlocked_package(self):
        for key, value in [("version", "0.1.0"), ("purl", "pkg:cargo/foreign@0.1.0"),
                            ("name", "foreign")]:
            with self.subTest(key=key):
                document = copy.deepcopy(self.document)
                document["components"][0][key] = value
                with self.assertRaises(ValueError):
                    self.validate(document)
        self.document["components"][0].update(name="foreign", version="1.0.0", purl="pkg:cargo/foreign@1.0.0")
        with self.assertRaisesRegex(ValueError, "selected Cargo.lock"):
            self.validate()

    def test_unknown_duplicated_or_disconnected_graph_fails(self):
        for deps in [[], [{"ref": "unknown", "dependsOn": []}],
                     [{"ref": "ref-chio-cli", "dependsOn": ["unknown"]}],
                     [{"ref": "ref-chio-cli", "dependsOn": []}],
                     self.document["dependencies"] * 2]:
            with self.subTest(deps=deps):
                document = copy.deepcopy(self.document)
                document["dependencies"] = deps
                with self.assertRaises(ValueError):
                    self.validate(document)

    def test_duplicate_component_reference_or_identity_property_fails(self):
        document = copy.deepcopy(self.document)
        document["components"][1]["bom-ref"] = document["components"][0]["bom-ref"]
        with self.assertRaisesRegex(ValueError, "component reference"):
            self.validate(document)
        self.document["components"][0]["properties"].append(
            self.document["components"][0]["properties"][0])
        with self.assertRaisesRegex(ValueError, "identity property"):
            self.validate()

    def test_format_tool_and_source_version_fail_closed(self):
        for key, value in [("bomFormat", "other"), ("specVersion", "1.5")]:
            with self.subTest(key=key):
                document = copy.deepcopy(self.document)
                document[key] = value
                with self.assertRaises(ValueError):
                    self.validate(document)
        self.document["metadata"]["tools"]["components"][0]["version"] = "1.18.0"
        with self.assertRaisesRegex(ValueError, "Syft version"):
            self.validate()
        with self.assertRaisesRegex(ValueError, "CLI source"):
            GATE.validate(self.document, self.binary, self.root, "0.1.0")

    def test_cli_checks_actual_files_and_refuses_ambiguous_json(self):
        sbom = self.root / "sbom.json"
        report = self.root / "report.json"
        sbom.write_text(json.dumps(self.document))
        command = [sys.executable, str(SCRIPT), "--root", str(self.root),
                   "--binary", str(self.binary), "--sbom", str(sbom),
                   "--expected-version", VERSION, "--report", str(report)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(report.read_text())["sbomSha256"], GATE.digest(sbom))
        sbom.write_text('{"components":[],"components":[]}')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate JSON", result.stderr)
        self.assertFalse(report.exists())

    def test_workflow_requires_validator_before_upload_on_all_platforms(self):
        root = SCRIPT.parents[1]
        workflow = (root / ".github/workflows/release-binaries.yml").read_text()
        self.assertIn(f"SYFT_VERSION={GATE.SYFT_VERSION}", workflow)
        self.assertIn(f'$syftVersion = "{GATE.SYFT_VERSION}"', workflow)
        index = workflow.index("      - name: Validate executable dependency inventory")
        end = workflow.index("      - name: Upload SBOM", index)
        block = workflow[index:end]
        self.assertNotIn("        if:", block)
        self.assertIn("python scripts/check-release-binary-sbom.py", block)
        self.assertIn('--expected-version "${GITHUB_REF_NAME#v}"', block)
        self.assertIn('--binary "target/${CHIO_TARGET}/release/${BINARY_NAME}${CHIO_BIN_SUFFIX}"', block)
        unix_stage = workflow[workflow.index("      - name: Stage artifacts (unix)"):
                              workflow.index("      - name: Stage artifacts (windows)")]
        windows_stage = workflow[workflow.index("      - name: Stage artifacts (windows)"):
                                 workflow.index("      - name: Write release metadata")]
        for suffix in ["cyclonedx.json", "validation.json"]:
            self.assertIn(f'cp "out/sbom/chio-${{CHIO_TARGET}}.{suffix}" "dist/${{stage_dir}}/"', unix_stage)
            self.assertIn(f'Copy-Item "out/sbom/chio-${{env:CHIO_TARGET}}.{suffix}" "dist/$stage/"', windows_stage)
            self.assertIn(f"            release/*.{suffix}", workflow)
        for path in [".github/workflows/ci.yml", "scripts/ci-workspace.sh"]:
            self.assertIn("scripts/tests/check-release-binary-sbom.test.py", (root / path).read_text())

    def test_macos_native_materials_are_required_and_travel_inside_signed_archive(self):
        root = SCRIPT.parents[1]
        workflow = (root / ".github/workflows/release-binaries.yml").read_text()
        prepare = workflow.index("      - name: Prepare pinned static OpenSSL (macOS)")
        scan = workflow.index("      - name: Scan prepared native OpenSSL (macOS)")
        build = workflow.index("      - name: Build (native)")
        linkage = workflow.index("      - name: Qualify macOS linkage and retain native materials")
        inventory = workflow.index("      - name: Validate executable dependency inventory")
        sign = workflow.index("      - name: Cosign sign-blob release archive")
        self.assertLess(prepare, scan)
        self.assertLess(scan, build)
        self.assertLess(build, linkage)
        self.assertLess(linkage, inventory)
        self.assertLess(inventory, sign)
        build_block = workflow[build:linkage]
        self.assertLess(build_block.index("cargo-env.sh"), build_block.index("cargo auditable build"))
        self.assertIn('if [[ "${RUNNER_OS}" == "macOS" ]]', build_block)
        native_block = workflow[linkage:workflow.index("      - name: Build (cross)")]
        self.assertIn("python scripts/check-macos-release-linkage.py", native_block)
        self.assertIn("LICENSE.txt", native_block)
        self.assertIn("python scripts/scan-macos-release-openssl.py", workflow[scan:build])
        self.assertNotIn("continue-on-error", workflow[scan:build])
        stage = workflow[workflow.index("      - name: Stage artifacts (unix)"):
                         workflow.index("      - name: Stage artifacts (windows)")]
        for suffix in ["native-openssl.json", "linkage.json", "openssl-LICENSE.txt",
                       "native-openssl.catalog.cdx.json", "native-openssl.grype.json",
                       "native-openssl-scan.json"]:
            self.assertIn(f'cp "out/native/chio-${{CHIO_TARGET}}.{suffix}" "dist/${{stage_dir}}/"', stage)
            self.assertIn(f"            release/*.{suffix}", workflow)
        for path in [".github/workflows/ci.yml", "scripts/ci-workspace.sh"]:
            self.assertIn("scripts/tests/macos-release-portability.test.py", (root / path).read_text())


if __name__ == "__main__":
    unittest.main()
