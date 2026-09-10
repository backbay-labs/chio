#!/usr/bin/env python3
"""Publication must reject stale, foreign, incomplete or failing source checks."""
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "check-release-source-gates.py"
SPEC = importlib.util.spec_from_file_location("release_gate", PATH)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REPOSITORY = "test/owned"
HEAD = "a" * 40


class SourceGate(unittest.TestCase):
    def setUp(self):
        self.responses = {}
        self.run_paths = []
        self.job_paths = []
        self.requests = []
        for i, (name, (event, required)) in enumerate(GATE.REQUIRED.items(), 1):
            prefix = f"repos/{REPOSITORY}/actions"
            workflow = {"id": i, "path": f".github/workflows/{name}"}
            run = {"id": i * 10, "run_number": 1, "run_attempt": 2,
                   "head_sha": HEAD, "head_branch": "main",
                   "head_repository": {"full_name": REPOSITORY},
                   "workflow_id": i, "path": workflow["path"],
                   "event": event or "workflow_dispatch",
                   "status": "completed", "conclusion": "success"}
            jobs = [{"name": n, "run_id": run["id"], "head_sha": HEAD,
                     "run_attempt": 2, "status": "completed", "conclusion": "success"}
                    for n in sorted(required)]
            self.responses[f"{prefix}/workflows/{name}"] = workflow
            run_path = f"{prefix}/workflows/{i}/runs?head_sha={HEAD}&branch=main&per_page=100"
            job_path = f"{prefix}/runs/{run['id']}/attempts/2/jobs?per_page=100"
            self.responses[run_path] = {"total_count": 1, "workflow_runs": [run]}
            self.responses[job_path] = {"total_count": len(jobs), "jobs": jobs}
            self.run_paths.append(run_path)
            self.job_paths.append(job_path)

    def read(self, path):
        self.requests.append(path)
        return copy.deepcopy(self.responses[path])

    def require(self):
        return GATE.require_gates(REPOSITORY, HEAD, self.read)

    def test_exact_source_latest_attempt_succeeds(self):
        self.assertEqual(len(self.require()), len(GATE.REQUIRED))
        self.assertTrue(all(path in self.requests for path in self.job_paths))

    def test_foreign_or_unreviewed_run_never_substitutes(self):
        for key, value in [("head_sha", "b" * 40), ("head_branch", "topic"),
                           ("head_repository", {"full_name": "foreign/fork"}),
                           ("workflow_id", 999), ("path", ".github/workflows/other.yml"),
                           ("event", "pull_request")]:
            with self.subTest(field=key):
                self.setUp()
                self.responses[self.run_paths[0]]["workflow_runs"][0][key] = value
                with self.assertRaises(ValueError):
                    self.require()

    def test_incomplete_failed_or_cancelled_run_refuses(self):
        for status, conclusion in [("in_progress", None), ("queued", None),
                                    ("completed", "failure"), ("completed", "cancelled"),
                                    ("completed", "skipped"), ("completed", "neutral")]:
            with self.subTest(status=status, conclusion=conclusion):
                self.setUp()
                self.responses[self.run_paths[1]]["workflow_runs"][0].update(
                    status=status, conclusion=conclusion)
                with self.assertRaises(ValueError):
                    self.require()

    def test_older_success_does_not_hide_latest_failure(self):
        data = self.responses[self.run_paths[0]]
        newer = copy.deepcopy(data["workflow_runs"][0])
        newer.update(id=999, run_number=2, conclusion="failure")
        data["workflow_runs"].append(newer)
        data["total_count"] += 1
        with self.assertRaises(ValueError):
            self.require()

    def test_required_job_binding_and_success(self):
        for key, value in [("head_sha", "b" * 40), ("run_id", 999), ("run_attempt", 1),
                           ("name", "unrelated"), ("status", "in_progress"),
                           ("conclusion", "failure"), ("conclusion", "skipped")]:
            with self.subTest(field=key, value=value):
                self.setUp()
                self.responses[self.job_paths[0]]["jobs"][0][key] = value
                with self.assertRaises(ValueError):
                    self.require()

    def test_missing_or_duplicate_required_job_refuses(self):
        for duplicate in [False, True]:
            with self.subTest(duplicate=duplicate):
                self.setUp()
                data = self.responses[self.job_paths[0]]
                if duplicate:
                    data["jobs"].append(copy.deepcopy(data["jobs"][0]))
                else:
                    data["jobs"].pop()
                data["total_count"] = len(data["jobs"])
                with self.assertRaises(ValueError):
                    self.require()

    def test_truncated_api_results_refuse(self):
        for kind in ["run", "job"]:
            self.setUp()
            path = (self.run_paths if kind == "run" else self.job_paths)[0]
            self.responses[path]["total_count"] += 1
            with self.assertRaises(ValueError):
                self.require()

    def test_missing_or_malformed_api_response_refuses(self):
        for value in [{}, {"total_count": 0, "workflow_runs": []}]:
            self.setUp()
            self.responses[self.run_paths[0]] = value
            with self.assertRaises((KeyError, ValueError)):
                self.require()

    def test_api_failure_is_not_success(self):
        def fail(_):
            raise OSError("unavailable")
        with self.assertRaises(OSError):
            GATE.require_gates(REPOSITORY, HEAD, fail)


class ReleaseCheckout(unittest.TestCase):
    """Exercise real Git state and manifest reads; only the network is replaced."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="chio-release-gate-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "crates/products/chio-cli").mkdir(parents=True)
        self.manifest = self.root / "crates/products/chio-cli/Cargo.toml"
        self.manifest.write_text('[package]\nversion = "0.1.1-rc.1"\n')
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.env = {"GITHUB_SHA": self.head, "GITHUB_REF_NAME": "v0.1.1-rc.1",
                    "GITHUB_REF_TYPE": "tag", "GITHUB_REPOSITORY": REPOSITORY}

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def run_main(self):
        output = io.StringIO()
        with patch.object(GATE, "__file__", str(self.root / "scripts/gate.py")), \
                patch.dict(os.environ, self.env, clear=True), \
                patch.object(GATE, "require_gates", return_value=[{"fixture": True}]) as remote, \
                contextlib.redirect_stdout(output):
            try:
                GATE.main()
            except (ValueError, subprocess.CalledProcessError):
                remote.assert_not_called()
                raise
            remote.assert_called_once_with(REPOSITORY, self.head)
        return json.loads(output.getvalue())

    def test_matching_tag_and_clean_exact_checkout_succeeds(self):
        self.assertEqual(self.run_main()["version"], "0.1.1-rc.1")

    def test_wrong_tag_ref_or_source_refuses_before_network(self):
        for key, value in [("GITHUB_REF_NAME", "v0.1.0"),
                           ("GITHUB_REF_TYPE", "branch"), ("GITHUB_SHA", "b" * 40)]:
            with self.subTest(field=key), patch.dict(self.env, {key: value}):
                with self.assertRaises(ValueError):
                    self.run_main()

    def test_dirty_tracked_checkout_refuses(self):
        self.manifest.write_text(self.manifest.read_text() + "# modified\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_main()

    def test_workspace_inherited_version_is_resolved(self):
        self.manifest.write_text('[package]\nversion.workspace = true\n')
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.1-rc.1"\n')
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "inherited version")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.env["GITHUB_SHA"] = self.head
        self.assertEqual(self.run_main()["version"], "0.1.1-rc.1")


if __name__ == "__main__":
    unittest.main()
