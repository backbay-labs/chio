#!/usr/bin/env python3
"""Exercise the workflow's path mapping; hosted cache save/restore is separate evidence."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/ci.yml').read_text()
JOB = WORKFLOW.split('\n  msrv:\n', 1)[1].split('\n  cargo-vet:\n', 1)[0]
MAPPING = textwrap.dedent(JOB.split("python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
PIN = 'e18b497796c12c097a38f9edb9d0641fb99eee32'


def joined_target(root, mapping):
    # Match the pinned action's src/config.ts:139-142, including path.join.
    script = '''const path = require('node:path');
const [root, mapping] = process.argv.slice(1);
let [workspace, target = 'target'] = mapping.trim().split('->').map(s => s.trim());
console.log(path.join(path.resolve(root, workspace), target));'''
    result = subprocess.run(['node', '-e', script, str(root), mapping],
                            check=True, capture_output=True, text=True)
    return Path(result.stdout.strip())


class MsrvCacheTarget(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='chio-msrv-cache-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def run_mapping(self, workspace, target):
        workspace.mkdir(parents=True, exist_ok=True)
        output = self.root / 'github-output'
        output.write_text('')
        environment = {**os.environ, 'GITHUB_WORKSPACE': str(workspace),
                       'CARGO_TARGET_DIR': str(target), 'GITHUB_OUTPUT': str(output)}
        subprocess.run([sys.executable, '-c', MAPPING], env=environment, check=True,
                       capture_output=True, text=True)
        line = output.read_text()
        self.assertTrue(line.startswith('workspace=. -> '))
        self.assertEqual(line.count('\n'), 1)
        mapping = line.removeprefix('workspace=').strip()
        self.assertEqual(joined_target(workspace, mapping), target.resolve())
        self.assertFalse(target.exists(), 'resolving the mapping must not create or erase build artifacts')
        return mapping

    def test_hosted_sibling_temp_directory_maps_to_actual_target(self):
        workspace = self.root / 'home/runner/work/chio/chio'
        target = self.root / 'home/runner/work/_temp/chio-msrv-target'
        mapping = self.run_mapping(workspace, target)
        self.assertEqual(mapping, '. -> ../../_temp/chio-msrv-target')

    def test_workspace_and_temp_names_with_spaces_are_preserved(self):
        self.run_mapping(self.root / 'checkout with spaces/repo',
                         self.root / 'temporary files/chio-msrv-target')

    def test_other_checkout_depths_do_not_assume_hosted_runner_layout(self):
        for number, depth in enumerate(('repo', 'work/group/project/repo', 'work/repo')):
            with self.subTest(depth=depth):
                self.run_mapping(self.root / depth, self.root / f'temp-{number}/chio-msrv-target')

    def test_absolute_rhs_reproduces_the_pinned_actions_wrong_directory(self):
        workspace = self.root / 'work/chio/chio'
        target = self.root / 'work/_temp/chio-msrv-target'
        self.assertNotEqual(joined_target(workspace, f'. -> {target}'), target)
        self.run_mapping(workspace, target)

    def test_the_job_has_one_cache_bound_to_the_actual_compile_directory(self):
        targets = [line.strip() for line in JOB.splitlines() if 'CARGO_TARGET_DIR:' in line]
        self.assertEqual(targets, ['CARGO_TARGET_DIR: ${{ runner.temp }}/chio-msrv-target'] * 2)
        self.assertIn('toolchain: "1.94.1"\n          cache: "false"', JOB)
        self.assertEqual(JOB.count('uses: Swatinem/rust-cache@' + PIN), 1)
        self.assertIn('workspaces: ${{ steps.msrv-cache.outputs.workspace }}', JOB)
        self.assertLess(JOB.index('python3 scripts/tests/msrv-cache-target.test.py'),
                        JOB.index('uses: Swatinem/rust-cache@'))
        self.assertLess(JOB.index('uses: Swatinem/rust-cache@'), JOB.index('name: MSRV workspace lane'))
        for unsupported in ('cache-on-failure:', 'cache-workspace-crates:', 'shared-key:', 'continue-on-error:', 'save-if:'):
            self.assertNotIn(unsupported, JOB)

    def test_all_existing_msrv_commands_and_limits_remain_required(self):
        self.assertIn('timeout-minutes: 240', JOB)
        lane = JOB.split('      - name: MSRV workspace lane\n', 1)[1]
        self.assertIn('CARGO_BUILD_JOBS: "1"', lane)
        self.assertIn('RUSTFLAGS: "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0"', lane)
        commands = textwrap.dedent(lane.split('        run: |\n', 1)[1]).strip().splitlines()
        self.assertEqual(commands, [
            'cargo build --workspace',
            'cargo test --workspace --exclude chio-conformance --exclude chio-wasm-guards --exclude chio-formal-diff-tests',
            'cargo test -p chio-formal-diff-tests --no-run',
            'cargo test -p chio-wasm-guards --lib',
        ])


if __name__ == '__main__':
    unittest.main()
