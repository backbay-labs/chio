#!/usr/bin/env python3
"""Collect tagged release subjects and verify the exact pinned SLSA builder policy."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

BUILDER_SHA = 'f7dd8c54c2067bafc12ca7a55595d5ee9b75204a'
BUILDER_ID = 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@' + BUILDER_SHA
BUILD_TYPE = 'https://github.com/slsa-framework/slsa-github-generator/generic@v1'
CALLER_WORKFLOW = '.github/workflows/release-binaries.yml'
COSIGN_VERSION = 'v2.4.1'
TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
           'x86_64-apple-darwin', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def pairs(values: list) -> dict:
    result = {}
    for key, value in values:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw: bytes) -> dict:
    result = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(result, dict), 'expected a JSON object')
    return result


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identities(repository: str, tag: str, source: str, run: str, attempt: str) -> None:
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is not None, 'invalid repository')
    require(re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', tag) is not None,
            'invalid release tag')
    require(re.fullmatch(r'[0-9a-f]{40}', source) is not None, 'invalid source SHA')
    require(re.fullmatch(r'[1-9][0-9]*', run) is not None and re.fullmatch(r'[1-9][0-9]*', attempt) is not None,
            'invalid build run identity')


def archive_names(tag: str) -> dict[str, str]:
    return {target: f'chio-{tag[1:]}-{target}.' + ('zip' if target.endswith('msvc') else 'tar.gz')
            for target in TARGETS}


def collect(artifacts: Path, repository: str, tag: str, source: str, run: str, attempt: str) -> dict:
    identities(repository, tag, source, run, attempt)
    expected_dirs = {artifacts / ('chio-' + target) for target in TARGETS}
    require(set(artifacts.iterdir()) == expected_dirs, 'release artifact target set differs from the five required targets')
    records = []
    for target, name in archive_names(tag).items():
        directory = artifacts / ('chio-' + target)
        require(directory.is_dir() and not directory.is_symlink(), 'unsafe release artifact directory')
        archive, metadata_path = directory / name, directory / 'release-metadata.json'
        expected = {'release_tag': tag, 'source_ref': 'refs/tags/' + tag, 'source_sha': source,
                    'version': tag[1:], 'workflow_run_id': run, 'workflow_run_attempt': attempt, 'target': target}
        require(metadata_path.is_file() and not metadata_path.is_symlink(), 'release metadata is missing')
        require(parse(metadata_path.read_bytes()) == expected, 'release metadata differs from original caller context')
        files = [p for p in directory.rglob('*') if p.name.endswith(('.tar.gz', '.zip'))]
        require(files == [archive], 'unexpected or missing archive in target artifact')
        for suffix in ('', '.sig', '.pem', '.sha256'):
            path = directory / (name + suffix)
            require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                    'release archive or signing material is missing')
        records.append({'name': name, 'sha256': digest(archive), 'target': target})
    subjects = ''.join(f'{record["sha256"]}  {record["name"]}\n' for record in sorted(records, key=lambda x: x['name']))
    return {'schema': 'chio.release-provenance-subjects.v1', 'repository': repository, 'release_tag': tag,
            'source_sha': source, 'run_id': run, 'run_attempt': attempt, 'archives': records,
            'subjects': base64.b64encode(subjects.encode()).decode()}


def statement_policy(statement: dict, archives: dict[str, str], repository: str,
                     tag: str, source: str, run: str, attempt: str) -> dict:
    identities(repository, tag, source, run, attempt)
    require(statement.get('_type') == 'https://in-toto.io/Statement/v0.1'
            and statement.get('predicateType') == 'https://slsa.dev/provenance/v0.2',
            'unexpected authenticated statement or predicate type')
    subjects = statement.get('subject')
    require(isinstance(subjects, list) and len(subjects) == len(TARGETS), 'incomplete provenance subject set')
    expected_names = set(archive_names(tag).values())
    found = {}
    for subject in subjects:
        require(isinstance(subject, dict), 'invalid provenance subject')
        name, hashes = subject.get('name'), subject.get('digest')
        require(isinstance(name, str) and name in expected_names and name not in found,
                'unexpected or duplicate provenance subject name')
        require(isinstance(hashes, dict) and set(hashes) == {'sha256'}
                and isinstance(hashes['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', hashes['sha256']) is not None, 'invalid subject digest')
        found[name] = hashes['sha256']
    require(set(found) == expected_names, 'provenance subject target set differs')
    require(all(name in found and found[name] == value for name, value in archives.items()),
            'authenticated subject digest differs from supplied archive')
    predicate = statement['predicate']
    require(isinstance(predicate, dict), 'invalid authenticated predicate')
    require(predicate.get('builder') == {'id': BUILDER_ID}, 'untrusted authenticated builder identity')
    require(predicate.get('buildType') == BUILD_TYPE, 'unexpected authenticated build type')
    source_uri = f'git+https://github.com/{repository}@refs/tags/{tag}'
    invocation = predicate['invocation']
    require(isinstance(invocation, dict), 'invalid authenticated invocation')
    require(invocation.get('configSource') == {'uri': source_uri, 'digest': {'sha1': source},
                                             'entryPoint': CALLER_WORKFLOW},
            'authenticated config source differs from intended release workflow, ref or commit')
    require(predicate.get('materials') == [{'uri': source_uri, 'digest': {'sha1': source}}],
            'authenticated materials differ from intended source')
    environment = invocation['environment']
    require(isinstance(environment, dict), 'invalid authenticated environment')
    expected = {'github_ref': 'refs/tags/' + tag, 'github_ref_type': 'tag', 'github_sha1': source,
                'github_run_id': run, 'github_run_attempt': attempt}
    require(all(environment.get(key) == value for key, value in expected.items()),
            'authenticated caller environment differs from intended release run')
    require(environment.get('github_event_name') in ('push', 'workflow_dispatch'),
            'authenticated event is not an original release event')
    require(isinstance(predicate['metadata'], dict), 'invalid authenticated metadata')
    require(predicate['metadata'].get('buildInvocationID') == f'{run}-{attempt}',
            'authenticated build invocation differs')
    return found


def invoke(args: list[str], prefix: Path) -> subprocess.CompletedProcess:
    timed_out = False
    try:
        result = subprocess.run(args, check=False, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        result = subprocess.CompletedProcess(args, 124, error.stdout or b'',
                                             (error.stderr or b'') + b'\nVerification command timed out.\n')
    Path(str(prefix) + '.stdout').write_bytes(result.stdout)
    Path(str(prefix) + '.stderr').write_bytes(result.stderr)
    Path(str(prefix) + '.command.json').write_text(json.dumps(
        {'args': args, 'exitCode': result.returncode, 'timedOut': timed_out}, indent=2) + '\n')
    return result


def verify(bundle: Path, archives: list[Path], repository: str, tag: str, source: str,
           run: str, attempt: str, evidence: Path, cosign: str) -> dict:
    identities(repository, tag, source, run, attempt)
    require(bool(archives) and len({p.name for p in archives}) == len(archives), 'duplicate or missing archive inputs')
    require(all(path.name in archive_names(tag).values() and path.is_file() and not path.is_symlink()
                for path in archives), 'unexpected archive input name or type')
    require(not evidence.exists(), 'verification evidence directory must be fresh')
    evidence.mkdir(parents=True)
    bundle_hash = digest(bundle)
    document = parse(bundle.read_bytes())
    require(document.get('mediaType') == 'application/vnd.dev.sigstore.bundle.v0.3+json', 'expected Sigstore bundle v0.3')
    material = document['verificationMaterial']
    require(isinstance(material, dict) and isinstance(material.get('tlogEntries'), list)
            and bool(material['tlogEntries']), 'missing transparency verification material')
    require(isinstance(material.get('certificate'), dict) and 'publicKey' not in material
            and bool(material['certificate'].get('rawBytes')), 'expected keyless certificate material')
    envelope = document['dsseEnvelope']
    require(isinstance(envelope, dict), 'invalid DSSE envelope')
    require(envelope.get('payloadType') == 'application/vnd.in-toto+json'
            and len(envelope.get('signatures', [])) == 1, 'unexpected DSSE payload or signature count')
    version = invoke([cosign, 'version', '--json'], evidence / 'cosign-version')
    require(version.returncode == 0 and parse(version.stdout).get('gitVersion') == COSIGN_VERSION,
            'unexpected cosign version')
    hashes = {path.name: digest(path) for path in archives}
    for path in archives:
        args = [cosign, 'verify-blob-attestation', '--new-bundle-format', '--bundle', str(bundle),
                '--certificate-identity', BUILDER_ID, '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                '--certificate-github-workflow-sha', source, '--certificate-github-workflow-repository', repository,
                '--certificate-github-workflow-ref', 'refs/tags/' + tag, str(path)]
        result = invoke(args, evidence / path.name)
        require(result.returncode == 0, 'cryptographic provenance verification failed; see retained cosign output')
    require(digest(bundle) == bundle_hash and all(digest(path) == hashes[path.name] for path in archives),
            'provenance or archive bytes changed during verification')
    # Only apply source/builder policy after the standard cryptographic verifier succeeds.
    statement = parse(base64.b64decode(envelope['payload'], validate=True))
    subjects = statement_policy(statement, hashes, repository, tag, source, run, attempt)
    result = {'schema': 'chio.verified-release-provenance.v1', 'passed': True,
              'repository': repository, 'tag': tag, 'sourceCommit': source, 'runId': run, 'runAttempt': attempt,
              'builderId': BUILDER_ID, 'cosignVersion': COSIGN_VERSION, 'bundleSha256': bundle_hash,
              'verifiedArchives': hashes, 'authenticatedSubjects': subjects,
              'scope': 'Exact upstream builder, artifact, release source and caller verification. Real-host acceptance and complete build-material inventory remain separate.'}
    (evidence / 'verified-statement.json').write_text(json.dumps(statement, indent=2) + '\n')
    (evidence / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    for command in ('subjects', 'verify'):
        p = sub.add_parser(command)
        for option in ('repository', 'tag', 'source-sha', 'run-id', 'run-attempt'):
            p.add_argument('--' + option, required=True)
        if command == 'subjects':
            p.add_argument('--artifacts', required=True, type=Path)
            p.add_argument('--report', required=True, type=Path)
            p.add_argument('--github-output', type=Path)
        else:
            p.add_argument('--bundle', required=True, type=Path)
            p.add_argument('--evidence', required=True, type=Path)
            p.add_argument('--cosign', default='cosign')
            p.add_argument('archives', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        if args.mode == 'subjects':
            require(not args.report.resolve().is_relative_to(args.artifacts.resolve()),
                    'subject report must not overwrite an artifact input')
            args.report.unlink(missing_ok=True)
            result = collect(args.artifacts, args.repository, args.tag, args.source_sha, args.run_id, args.run_attempt)
            args.report.write_text(json.dumps(result, indent=2) + '\n')
            if args.github_output:
                with args.github_output.open('a') as output:
                    for key in ('subjects', 'release_tag', 'source_sha'):
                        output.write(f'{key}={result[key]}\n')
        else:
            result = verify(args.bundle, args.archives, args.repository, args.tag, args.source_sha,
                            args.run_id, args.run_attempt, args.evidence, args.cosign)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'Release provenance refused: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
