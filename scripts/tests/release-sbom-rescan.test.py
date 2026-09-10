#!/usr/bin/env python3
"""Adversarial controls for SBOM comparison and authenticated archive orchestration."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPARE = load('source_comparison', 'check-source-sbom-determinism.py')
RESCAN = load('release_rescan', 'rescan-release-sboms.py')
VERSION = '0.1.1-rc.1'
TARGET = 'aarch64-apple-darwin'
STAGE = f'chio-{VERSION}-{TARGET}'


class SourceInventoryComparison(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='chio-source-sbom-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
                         'serialNumber': 'urn:uuid:00000000-0000-4000-8000-000000000001',
                         'metadata': {'timestamp': '2026-09-10T06:00:00Z',
                                      'component': {'type': 'file', 'name': '.', 'bom-ref': 'source'},
                                      'tools': {'components': [{'name': 'syft', 'version': '1.51.1'}]}},
                         'components': [{'bom-ref': 'package', 'name': 'example', 'version': '1.0.0',
                                         'hashes': [{'alg': 'SHA-256', 'content': 'a' * 64}]}],
                         'dependencies': [{'ref': 'source', 'dependsOn': ['package']}]}

    def compare(self, second=None):
        first, other = self.root / 'first.json', self.root / 'second.json'
        first.write_text(json.dumps(self.document))
        other.write_text(json.dumps(second if second is not None else self.document))
        return COMPARE.compare(first, other)

    def test_generated_run_metadata_only_may_differ(self):
        other = copy.deepcopy(self.document)
        other['serialNumber'] = 'urn:uuid:00000000-0000-4000-8000-000000000002'
        other['metadata']['timestamp'] = '2026-09-10T07:00:00Z'
        result = self.compare(other)
        self.assertTrue(result['passed'])
        self.assertNotEqual(result['firstSha256'], result['secondSha256'])
        self.assertEqual(result['excludedGeneratedFields'], ['serialNumber', 'metadata.timestamp'])

    def test_inventory_graph_hash_and_other_metadata_changes_fail(self):
        for field in ['version', 'hash', 'graph', 'tool', 'component-count', 'source-name']:
            with self.subTest(field=field):
                other = copy.deepcopy(self.document)
                if field == 'version': other['components'][0]['version'] = '2.0.0'
                if field == 'hash': other['components'][0]['hashes'][0]['content'] = 'b' * 64
                if field == 'graph': other['dependencies'][0]['dependsOn'] = []
                if field == 'tool': other['metadata']['tools']['components'][0]['version'] = '1.18.1'
                if field == 'component-count': other['components'].append({'name': 'new'})
                if field == 'source-name': other['metadata']['component']['name'] = 'different'
                with self.assertRaises(ValueError): self.compare(other)

    def test_json_types_are_not_silently_coerced_during_comparison(self):
        self.document['version'] = 1
        other = copy.deepcopy(self.document); other['version'] = True
        with self.assertRaises(ValueError): self.compare(other)

    def test_empty_wrong_format_binary_scan_and_bad_run_fields_fail(self):
        for field, value in [('components', []), ('specVersion', '1.5'), ('serialNumber', 'bad')]:
            with self.subTest(field=field):
                other = copy.deepcopy(self.document); other[field] = value
                with self.assertRaises(ValueError): COMPARE.normalized(other)
        for value in ['bad', '2026-09-10T07:00:00', None]:
            other = copy.deepcopy(self.document); other['metadata']['timestamp'] = value
            with self.assertRaises(ValueError): COMPARE.normalized(other)
        self.document['metadata']['component']['version'] = 'sha256:' + 'a' * 64
        with self.assertRaises(ValueError): COMPARE.normalized(self.document)

    def test_duplicate_json_keys_and_failed_retry_leave_no_pass_report(self):
        first, second, report = [self.root / name for name in ('first', 'second', 'report')]
        first.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}')
        second.write_text(json.dumps(self.document)); report.write_text('{"passed":true}')
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/check-source-sbom-determinism.py'),
                                 '--first', str(first), '--second', str(second), '--report', str(report)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('duplicate JSON key', result.stderr)
        self.assertFalse(report.exists())


class AuthenticatedArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='chio-archive-rescan-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, entries, suffix='tar.gz'):
        path = self.root / (STAGE + '.' + suffix)
        if suffix == 'zip':
            with zipfile.ZipFile(path, 'w') as archive:
                for name, data, kind in entries:
                    item = zipfile.ZipInfo(name); item.external_attr = kind << 16
                    archive.writestr(item, data)
        else:
            with tarfile.open(path, 'w:gz') as archive:
                for name, data, kind in entries:
                    item = tarfile.TarInfo(name); item.type = kind; item.size = len(data)
                    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): item.linkname = '../outside'
                    archive.addfile(item, io.BytesIO(data))
        return path

    def test_regular_tar_and_zip_extract_only_exact_binary(self):
        for suffix, kind in [('tar.gz', tarfile.REGTYPE), ('zip', stat.S_IFREG)]:
            with self.subTest(suffix=suffix):
                path = self.archive([(STAGE + '/chio', b'synthetic binary', kind),
                                     (STAGE + '/LICENSE', b'license', kind)], suffix)
                destination = self.root / ('chio-' + suffix)
                RESCAN.extract_binary(path, STAGE, 'chio', destination)
                self.assertEqual(destination.read_bytes(), b'synthetic binary')
                self.assertFalse((self.root / 'LICENSE').exists())

    def test_unsafe_paths_duplicates_links_and_wrong_binary_fail_before_write(self):
        for suffix, regular, link in [('tar.gz', tarfile.REGTYPE, tarfile.SYMTYPE),
                                      ('zip', stat.S_IFREG, stat.S_IFLNK)]:
            for name in ['../outside', '/absolute', STAGE + '/../outside', STAGE + '/./chio',
                         STAGE + '//chio', STAGE + '\\chio', 'wrong-stage/chio']:
                with self.subTest(suffix=suffix, name=name):
                    path = self.archive([(name, b'bad', regular)], suffix)
                    with self.assertRaises(ValueError): RESCAN.extract_binary(path, STAGE, 'chio', self.root / 'out')
            for entries in [[(STAGE + '/chio', b'link', link)],
                            [(STAGE + '/chio', b'a', regular), (STAGE + '/chio', b'b', regular)],
                            [(STAGE + '/other', b'a', regular)], [(STAGE + '/chio', b'', regular)]]:
                path = self.archive(entries, suffix)
                destination = self.root / ('out-' + suffix)
                destination.unlink(missing_ok=True)
                with self.assertRaises(ValueError): RESCAN.extract_binary(path, STAGE, 'chio', destination)
        self.assertFalse((self.root / 'outside').exists())

    def signing_inputs(self):
        archive = self.archive([(STAGE + '/chio', b'synthetic binary', tarfile.REGTYPE)])
        Path(str(archive) + '.sig').write_text('synthetic signature fixture')
        Path(str(archive) + '.pem').write_text('synthetic certificate fixture')
        return archive

    def test_verifier_pins_identity_issuer_repository_ref_and_source_without_bypass_flags(self):
        archive = self.signing_inputs()
        with patch.object(RESCAN, 'command') as command:
            result = RESCAN.verify_archive(archive, 'example/chio', 'v' + VERSION, 'a' * 40, self.root / 'verify')
        args = command.call_args.args[0]
        self.assertIn('https://github.com/example/chio/.github/workflows/release-binaries.yml@refs/tags/v' + VERSION, args)
        for flag, value in [('--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'),
                            ('--certificate-github-workflow-repository', 'example/chio'),
                            ('--certificate-github-workflow-ref', 'refs/tags/v' + VERSION),
                            ('--certificate-github-workflow-sha', 'a' * 40)]:
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertFalse(any('ignore' in value or value == '--key' for value in args))
        self.assertEqual(result['archiveSha256'], RESCAN.digest(archive))

    def test_changed_archive_after_verification_is_refused(self):
        archive = self.signing_inputs()
        with patch.object(RESCAN, 'command', side_effect=lambda *_: archive.write_bytes(b'changed')):
            with self.assertRaisesRegex(ValueError, 'changed during signature'):
                RESCAN.verify_archive(archive, 'example/chio', 'v' + VERSION, 'a' * 40, self.root / 'verify')

    def test_incomplete_target_set_and_signature_failure_never_parse_or_scan(self):
        assets = self.root / 'assets'; assets.mkdir()
        with patch.object(RESCAN.GATE, 'expected_packages'), patch.object(RESCAN, 'verify_source_tree'), \
                patch.object(RESCAN, 'extract_binary') as extract:
            with self.assertRaisesRegex(ValueError, 'target set'):
                RESCAN.rescan(assets, self.root, self.root / 'out1', self.root / 'work1',
                              'example/chio', 'v' + VERSION, 'a' * 40)
            for target in RESCAN.TARGETS:
                name = f'chio-{VERSION}-{target}.' + ('zip' if target.endswith('msvc') else 'tar.gz')
                for suffix in ['', '.sig', '.pem']:
                    (assets / (name + suffix)).write_bytes(b'synthetic fixture')
            with patch.object(RESCAN, 'verify_archive', side_effect=ValueError('signature refused')):
                with self.assertRaisesRegex(ValueError, 'signature refused'):
                    RESCAN.rescan(assets, self.root, self.root / 'out2', self.root / 'work2',
                                  'example/chio', 'v' + VERSION, 'a' * 40)
            extract.assert_not_called()
        self.assertFalse((self.root / 'out2/authenticated-rescan.json').exists())

    def test_source_tree_must_match_signed_commit_and_be_clean(self):
        for results in [[subprocess.CompletedProcess([], 0, 'b' * 40, '')],
                        [subprocess.CompletedProcess([], 0, 'a' * 40, ''),
                         subprocess.CompletedProcess([], 0, ' M Cargo.lock', '')]]:
            with patch.object(RESCAN.subprocess, 'run', side_effect=results):
                with self.assertRaises(ValueError): RESCAN.verify_source_tree(self.root, 'a' * 40)
        with patch.object(RESCAN.subprocess, 'run', side_effect=[
                subprocess.CompletedProcess([], 0, 'a' * 40, ''), subprocess.CompletedProcess([], 0, '', '')]):
            RESCAN.verify_source_tree(self.root, 'a' * 40)

    def test_verifier_failure_is_retained_and_propagated(self):
        archive = self.signing_inputs()
        with patch.object(RESCAN, 'command', side_effect=ValueError('signature refused')):
            with self.assertRaises(ValueError):
                RESCAN.verify_archive(archive, 'example/chio', 'v' + VERSION, 'a' * 40, self.root / 'verify')
        self.assertEqual((self.root / (archive.name + '.refused-input')).read_bytes(), archive.read_bytes())
        with patch.object(RESCAN.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)):
            with self.assertRaisesRegex(ValueError, 'failed'):
                RESCAN.command(['cosign', 'verify-blob'], self.root / 'target.cosign')
        record = json.loads((self.root / 'target.cosign.command.json').read_text())
        self.assertEqual(record['exitCode'], 7)

    def test_workflow_keeps_full_comparison_authentication_and_both_raw_source_inventories(self):
        workflow = (ROOT / '.github/workflows/sbom.yml').read_text()
        self.assertIn('git worktree add --detach "${source_dir}" "${source_sha}"', workflow)
        self.assertIn('python3 scripts/check-source-sbom-determinism.py', workflow)
        self.assertIn('second="${GITHUB_WORKSPACE}/${OUT_DIR}/source-repeat.cdx.json"', workflow)
        self.assertIn("if: always() && steps.release.outputs.out_dir != ''", workflow)
        self.assertIn('python3 scripts/rescan-release-sboms.py', workflow)
        self.assertNotIn('cmp "${first}" "${second}"', workflow)
        self.assertLess(workflow.index('python3 scripts/rescan-release-sboms.py'), workflow.index('cosign sign-blob --yes'))
        self.assertIn('include-dev-dependencies: true', (ROOT / 'deploy/sbom/syft.yaml').read_text())
        for file in ['scripts/ci-workspace.sh', '.github/workflows/ci.yml']:
            self.assertIn('python3 scripts/tests/release-sbom-rescan.test.py', (ROOT / file).read_text())


if __name__ == '__main__':
    unittest.main()
