#!/usr/bin/env python3
"""Mutation tests for provenance policy and workflow wiring, not signed host acceptance."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('provenance_gate', ROOT / 'scripts/verify-release-provenance.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
REPO, TAG, SOURCE, RUN, ATTEMPT = 'example/chio', 'v0.1.1-rc.1', 'a' * 40, '12345', '2'


class ProvenanceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='chio-provenance-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / 'artifacts'; self.artifacts.mkdir()
        self.archives = {}
        for target, name in GATE.archive_names(TAG).items():
            directory = self.artifacts / ('chio-' + target); directory.mkdir()
            archive = directory / name; archive.write_bytes(('synthetic archive: ' + target).encode())
            self.archives[name] = archive
            for suffix in ('.sig', '.pem', '.sha256'): (directory / (name + suffix)).write_text('synthetic fixture')
            (directory / 'release-metadata.json').write_text(json.dumps({
                'release_tag': TAG, 'source_ref': 'refs/tags/' + TAG, 'source_sha': SOURCE,
                'version': TAG[1:], 'workflow_run_id': RUN, 'workflow_run_attempt': ATTEMPT, 'target': target}))
        uri = f'git+https://github.com/{REPO}@refs/tags/{TAG}'
        self.statement = {'_type': 'https://in-toto.io/Statement/v0.1',
                          'predicateType': 'https://slsa.dev/provenance/v0.2',
                          'subject': [{'name': name, 'digest': {'sha256': GATE.digest(path)}}
                                      for name, path in self.archives.items()],
                          'predicate': {'builder': {'id': GATE.BUILDER_ID}, 'buildType': GATE.BUILD_TYPE,
                                        'invocation': {'configSource': {'uri': uri, 'digest': {'sha1': SOURCE},
                                                                        'entryPoint': GATE.CALLER_WORKFLOW},
                                                       'environment': {'github_ref': 'refs/tags/' + TAG,
                                                                       'github_ref_type': 'tag', 'github_sha1': SOURCE,
                                                                       'github_run_id': RUN, 'github_run_attempt': ATTEMPT,
                                                                       'github_event_name': 'push'}},
                                        'metadata': {'buildInvocationID': RUN + '-' + ATTEMPT},
                                        'materials': [{'uri': uri, 'digest': {'sha1': SOURCE}}]}}
        self.bundle = self.root / 'bundle.json'
        self.write_bundle()

    def write_bundle(self, statement=None):
        document = {'mediaType': 'application/vnd.dev.sigstore.bundle.v0.3+json',
                    'verificationMaterial': {'certificate': {'rawBytes': 'synthetic certificate'},
                                             'tlogEntries': [{'logIndex': 'synthetic fixture'}]},
                    'dsseEnvelope': {'payloadType': 'application/vnd.in-toto+json',
                                     'payload': base64.b64encode(json.dumps(statement or self.statement).encode()).decode(),
                                     'signatures': [{'sig': 'synthetic fixture'}]}}
        self.bundle.write_text(json.dumps(document))

    def collect(self):
        return GATE.collect(self.artifacts, REPO, TAG, SOURCE, RUN, ATTEMPT)

    def policy(self, statement=None):
        return GATE.statement_policy(statement or self.statement,
                                     {name: GATE.digest(path) for name, path in self.archives.items()},
                                     REPO, TAG, SOURCE, RUN, ATTEMPT)

    def verify(self):
        return GATE.verify(self.bundle, list(self.archives.values()), REPO, TAG, SOURCE, RUN, ATTEMPT,
                           self.root / 'evidence', 'cosign')

    def fake_cosign(self, args, **_kwargs):
        output = json.dumps({'gitVersion': GATE.COSIGN_VERSION}).encode() if 'version' in args else b''
        return subprocess.CompletedProcess(args, 0, output, b'synthetic command fixture')

    def test_complete_subjects_bind_real_fixture_bytes_with_canonical_names(self):
        result = self.collect()
        lines = base64.b64decode(result['subjects']).decode().splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines:
            checksum, name = line.split('  ')
            self.assertEqual(checksum, GATE.digest(self.archives[name]))
            self.assertNotIn('/', name)
        self.assertEqual(len(self.policy()), 5)

    def test_every_metadata_field_is_bound_to_original_context(self):
        path = next(self.artifacts.glob('*/release-metadata.json')); original = path.read_text()
        for field in json.loads(original):
            with self.subTest(field=field):
                document = json.loads(original); document[field] = 'foreign'; path.write_text(json.dumps(document))
                with self.assertRaisesRegex(ValueError, 'original caller'): self.collect()
        path.write_text(original)
        document = json.loads(original); del document['workflow_run_attempt']; path.write_text(json.dumps(document))
        with self.assertRaises(ValueError): self.collect()

    def test_incomplete_extra_target_and_missing_signing_material_fail(self):
        extra = self.artifacts / 'foreign'; extra.mkdir()
        with self.assertRaises(ValueError): self.collect()
        extra.rmdir()
        archive = next(iter(self.archives.values())); signature = Path(str(archive) + '.sig'); signature.unlink()
        with self.assertRaises(ValueError): self.collect()
        signature.write_text('synthetic fixture'); archive.unlink()
        with self.assertRaises(ValueError): self.collect()

    def test_duplicate_missing_and_relabelled_subjects_or_changed_digests_fail(self):
        for mutation in ['missing', 'duplicate', 'name', 'digest']:
            with self.subTest(mutation=mutation):
                statement = copy.deepcopy(self.statement)
                if mutation == 'missing': statement['subject'].pop()
                if mutation == 'duplicate': statement['subject'][1] = statement['subject'][0]
                if mutation == 'name': statement['subject'][0]['name'] = '../foreign'
                if mutation == 'digest': statement['subject'][0]['digest']['sha256'] = '0' * 64
                with self.assertRaises(ValueError): self.policy(statement)

    def test_only_exact_builder_revision_and_build_type_are_trusted(self):
        for value in [GATE.BUILDER_ID.replace(GATE.BUILDER_SHA, 'refs/tags/v2.1.0'),
                      GATE.BUILDER_ID.replace(GATE.BUILDER_SHA, 'b' * 40), 'https://example.com/builder']:
            statement = copy.deepcopy(self.statement); statement['predicate']['builder']['id'] = value
            with self.assertRaises(ValueError): self.policy(statement)
        statement = copy.deepcopy(self.statement); statement['predicate']['buildType'] = 'foreign'
        with self.assertRaises(ValueError): self.policy(statement)

    def test_config_source_and_materials_must_both_match(self):
        for field in ['uri', 'digest', 'entryPoint']:
            statement = copy.deepcopy(self.statement)
            statement['predicate']['invocation']['configSource'][field] = 'foreign'
            with self.assertRaises(ValueError): self.policy(statement)
        for value in [[], [{'uri': 'foreign', 'digest': {'sha1': SOURCE}}],
                      self.statement['predicate']['materials'] * 2]:
            statement = copy.deepcopy(self.statement); statement['predicate']['materials'] = value
            with self.assertRaises(ValueError): self.policy(statement)

    def test_signed_event_environment_and_invocation_must_match_caller(self):
        for field in self.statement['predicate']['invocation']['environment']:
            statement = copy.deepcopy(self.statement)
            statement['predicate']['invocation']['environment'][field] = 'workflow_run' if field == 'github_event_name' else 'foreign'
            with self.assertRaises(ValueError): self.policy(statement)
        statement = copy.deepcopy(self.statement); statement['predicate']['metadata']['buildInvocationID'] = RUN + '-1'
        with self.assertRaises(ValueError): self.policy(statement)

    def test_standard_verifier_flags_pin_identity_source_and_keep_crypto_checks(self):
        with patch.object(GATE.subprocess, 'run', side_effect=self.fake_cosign) as invoke:
            result = self.verify()
        self.assertTrue(result['passed'])
        for call in invoke.call_args_list[1:]:
            args = call.args[0]
            for flag, value in [('--certificate-identity', GATE.BUILDER_ID),
                                ('--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'),
                                ('--certificate-github-workflow-sha', SOURCE),
                                ('--certificate-github-workflow-repository', REPO),
                                ('--certificate-github-workflow-ref', 'refs/tags/' + TAG)]:
                self.assertEqual(args[args.index(flag) + 1], value)
            self.assertIn('--new-bundle-format', args)
            self.assertFalse(any('ignore' in value or value == '--key' for value in args))

    def test_crypto_failure_never_runs_policy_or_creates_pass_report(self):
        def refuse(args, **kwargs):
            return self.fake_cosign(args, **kwargs) if 'version' in args else subprocess.CompletedProcess(args, 1, b'', b'refused')
        with patch.object(GATE.subprocess, 'run', side_effect=refuse), patch.object(GATE, 'statement_policy') as policy:
            with self.assertRaisesRegex(ValueError, 'cryptographic'): self.verify()
            policy.assert_not_called()
        self.assertFalse((self.root / 'evidence/verification.json').exists())

    def test_timeout_and_changed_bundle_fail_without_pass_report(self):
        def changed(args, **kwargs):
            if 'version' not in args: self.bundle.write_bytes(self.bundle.read_bytes() + b' ')
            return self.fake_cosign(args, **kwargs)
        with patch.object(GATE.subprocess, 'run', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during'): self.verify()
        self.assertFalse((self.root / 'evidence/verification.json').exists())
        with patch.object(GATE.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['cosign'], 90)):
            result = GATE.invoke(['cosign'], self.root / 'timeout')
            self.assertEqual(result.returncode, 124)
            self.assertTrue(json.loads((self.root / 'timeout.command.json').read_text())['timedOut'])

    def test_key_only_bundle_or_missing_transparency_material_is_refused(self):
        document = json.loads(self.bundle.read_text())
        for field in ['publicKey', 'tlogEntries']:
            other = copy.deepcopy(document)
            if field == 'publicKey': other['verificationMaterial']['publicKey'] = {'hint': 'foreign'}
            else: other['verificationMaterial']['tlogEntries'] = []
            self.bundle.write_text(json.dumps(other))
            with patch.object(GATE.subprocess, 'run') as invoke:
                if (self.root / 'evidence').exists(): (self.root / 'evidence').rmdir()
                with self.assertRaises(ValueError): self.verify()
                invoke.assert_not_called()

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError): GATE.parse(b'{"a":1,"a":2}')

    def test_workflow_uses_original_context_immutable_builder_and_verified_attachment(self):
        release = (ROOT / '.github/workflows/release-binaries.yml').read_text()
        workflow = (ROOT / '.github/workflows/slsa.yml').read_text()
        self.assertIn('uses: ./.github/workflows/slsa.yml', release)
        self.assertIn('  workflow_call:', workflow)
        self.assertNotIn('  workflow_run:', workflow)
        self.assertNotIn('github.event.workflow_run', workflow)
        self.assertIn('@' + GATE.BUILDER_SHA, workflow)
        self.assertIn('compile-generator: true', workflow)
        self.assertIn('upload-assets: false', workflow)
        self.assertLess(workflow.index('verify-release-provenance.py verify'), workflow.index('gh release upload'))
        command_lines = [line for line in workflow.splitlines() if not line.lstrip().startswith('#')]
        self.assertFalse(any('--clobber' in line or 'continue-on-error' in line for line in command_lines))
        self.assertIn('"workflow_run_attempt": "${GITHUB_RUN_ATTEMPT}"', release)
        self.assertIn('"target": "${CHIO_TARGET}"', release)
        for path in ['scripts/ci-workspace.sh', '.github/workflows/ci.yml']:
            self.assertIn('python3 scripts/tests/release-provenance.test.py', (ROOT / path).read_text())


if __name__ == '__main__':
    unittest.main()
