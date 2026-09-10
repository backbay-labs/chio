#!/usr/bin/env python3
"""Exercise byte-preserving candidate staging with disposable assets and API fixtures."""
import copy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("draft_assets", ROOT / "scripts/check-release-draft-assets.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REPO = "backbay-labs/chio"
TAG = "v0.1.1-rc.1"
SOURCE = "a" * 40


class DraftAssets(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="chio-draft-assets-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.release = {"id": 7, "tag_name": TAG, "draft": True, "prerelease": True}
        self.ref = {"object": {"type": "commit", "sha": SOURCE}}
        self.assets = []
        for index, name in enumerate(sorted(GATE.required_names(TAG, SOURCE)), 1):
            body = (name + " fixture\n").encode()
            (self.directory / name).write_bytes(body)
            self.assets.append({"id": index, "name": name, "size": len(body), "state": "uploaded",
                                "digest": "sha256:" + hashlib.sha256(body).hexdigest()})

    def read(self, endpoint):
        if endpoint.endswith("/releases?per_page=100&page=1"):
            return [self.release]
        if "/git/ref/tags/" in endpoint:
            return self.ref
        if endpoint.endswith("/releases/7/assets?per_page=100&page=1"):
            return self.assets
        raise AssertionError(endpoint)

    def snapshot(self, **kwargs):
        return GATE.snapshot(REPO, TAG, SOURCE, self.directory, read=self.read, **kwargs)

    def test_complete_draft_and_same_bytes_after_publication(self):
        before = self.snapshot()
        self.release["draft"] = False
        self.assertEqual(before, self.snapshot(published=True))
        with self.assertRaises(ValueError):
            self.snapshot()
        with self.assertRaises(ValueError):
            GATE.require_stage(REPO, TAG, self.read)

    def test_candidate_stage_allows_absent_or_draft_only(self):
        GATE.require_stage(REPO, TAG, lambda _: [])
        GATE.require_stage(REPO, TAG, self.read)
        self.release["prerelease"] = False
        with self.assertRaises(ValueError):
            GATE.require_stage(REPO, TAG, self.read)

    def test_missing_provenance_signature_sbom_or_native_material_refuses(self):
        for suffix in ("intoto.jsonl", ".sig", "cyclonedx.json", "native-openssl-scan.json"):
            with self.subTest(suffix=suffix):
                original = self.assets
                self.assets = [a for a in original if not a["name"].endswith(suffix)]
                with self.assertRaises(ValueError):
                    self.snapshot()
                self.assets = original

    def test_modified_local_bytes_refuse_even_at_same_size(self):
        file = self.directory / self.assets[0]["name"]
        file.write_bytes(b"X" * file.stat().st_size)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_remote_digest_size_and_state_are_required(self):
        for field, value in (("digest", None), ("size", 0), ("state", "starter"), ("id", False)):
            with self.subTest(field=field):
                original = copy.deepcopy(self.assets)
                self.assets[0][field] = value
                with self.assertRaises(ValueError):
                    self.snapshot()
                self.assets = original

    def test_changed_asset_id_changes_qualification_identity(self):
        before = self.snapshot()
        self.assets[0]["id"] += 1000
        self.assertNotEqual(before, self.snapshot())

    def test_changed_tag_source_refuses(self):
        self.ref["object"]["sha"] = "b" * 40
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_duplicates_extra_files_and_symlinks_refuse(self):
        self.assets.append(copy.deepcopy(self.assets[0]))
        with self.assertRaises(ValueError):
            self.snapshot()
        self.assets.pop()
        extra = self.directory / "unrecorded"
        extra.write_text("extra")
        with self.assertRaises(ValueError):
            self.snapshot()
        extra.unlink()
        file = self.directory / self.assets[0]["name"]
        body = file.read_bytes()
        file.unlink()
        extra.write_bytes(body)
        file.symlink_to(extra)
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_asset_names_cannot_escape_download_directory(self):
        for name in ("../outside", "/absolute", "..", "nested/file", "bad\\name"):
            with self.subTest(name=name):
                before = self.assets[0]["name"]
                self.assets[0]["name"] = name
                with self.assertRaises(ValueError):
                    self.snapshot()
                self.assets[0]["name"] = before

    def test_manifest_mismatch_refuses_without_mutating_either_file(self):
        before = self.snapshot()
        file = self.directory / self.assets[0]["name"]
        file.write_bytes(b"new bytes")
        self.assets[0].update(size=9, digest="sha256:" + hashlib.sha256(b"new bytes").hexdigest())
        self.assertNotEqual(before, self.snapshot())

    def test_checksum_review_requires_merged_canonical_pr_and_exact_bytes(self):
        identity = self.snapshot()
        pr = {"merged": True, "state": "closed", "merge_commit_sha": "b" * 40,
              "base": {"ref": "main", "repo": {"full_name": REPO}}}
        files = [{"filename": f"supply-chain/checksums/{TAG}.txt{suffix}", "status": "added"}
                 for suffix in ("", ".sig", ".pem")]
        altered = False

        def read(endpoint):
            if endpoint.endswith("/pulls/42"):
                return pr
            if "/pulls/42/files?" in endpoint:
                return files
            if "/contents/" in endpoint:
                path = endpoint.split("/contents/", 1)[1].split("?", 1)[0]
                body = (self.directory / Path(path).name).read_bytes()
                return {"path": path, "type": "file", "encoding": "base64",
                        "content": base64.b64encode(b"changed" if altered else body).decode()}
            raise AssertionError(endpoint)

        GATE.require_checksum_review(identity, 42, read)
        pr["merged"] = False
        with self.assertRaises(ValueError):
            GATE.require_checksum_review(identity, 42, read)
        pr["merged"] = True
        pr["base"]["repo"]["full_name"] = "other/chio"
        with self.assertRaises(ValueError):
            GATE.require_checksum_review(identity, 42, read)
        pr["base"]["repo"]["full_name"] = REPO
        altered = True
        with self.assertRaises(ValueError):
            GATE.require_checksum_review(identity, 42, read)
        altered = False
        files.append({"filename": "unrelated", "status": "added"})
        with self.assertRaises(ValueError):
            GATE.require_checksum_review(identity, 42, read)

    def test_checksum_review_missing_number_refuses(self):
        with self.assertRaises(ValueError):
            GATE.require_checksum_review(self.snapshot(), 0, lambda _: self.fail("must not contact GitHub"))

    def test_workflow_classifies_prerelease_before_build_metadata(self):
        source = (ROOT / ".github/workflows/release-binaries.yml").read_text()
        blocks = re.findall(r'          version_core="\$\{version%%\+\*\}"\n(.*?)          fi\n', source, re.S)
        self.assertEqual(len(blocks), 2)
        for version, expected in (("0.1.1-rc.1", "true"), ("1.2.3-rc.1+build", "true"),
                                  ("1.2.3", "false"), ("1.2.3+build-42", "false")):
            with self.subTest(version=version):
                output = self.directory / "mode-output"
                output.write_text("")
                script = 'version_core="${version%%+*}"\n' + blocks[0] + "fi\n"
                subprocess.run(["bash", "-eu", "-c", script], check=True,
                               env={**os.environ, "version": version, "GITHUB_OUTPUT": str(output)})
                self.assertEqual(output.read_text(), f"prerelease={expected}\n")
        self.assertIn("overwrite_files: false", source)
        self.assertIn("check-release-draft-assets.py stage", source)
        self.assertIn("name: Candidate checksum review remains pending with the operator", source)
        self.assertIn("name: Open checksum index PR\n        if: steps.checksum_release.outputs.prerelease != 'true'", source)
        slsa = (ROOT / ".github/workflows/slsa.yml").read_text()
        self.assertIn("upload-assets: false", slsa)
        self.assertIn("Verify pinned provenance before attachment", slsa)
        self.assertIn("gh release upload", slsa)
        self.assertIn('if [[ "${draft_state}" != "true" ]]', slsa)


if __name__ == "__main__":
    unittest.main()
