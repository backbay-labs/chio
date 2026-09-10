#!/usr/bin/env python3
"""Authenticate release archives before extracting and inventorying their executables."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile


TARGETS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
           'x86_64-apple-darwin', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc')
SCRIPT = Path(__file__).resolve().parent / 'check-release-binary-sbom.py'
SPEC = importlib.util.spec_from_file_location('release_binary_sbom', SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def member_name(name: str, stage: str) -> str:
    require('\\' not in name and '\x00' not in name, 'invalid archive member path')
    clean = name.rstrip('/')
    path = PurePosixPath(clean)
    require(not path.is_absolute() and all(part not in ('', '.', '..') for part in clean.split('/')),
            'unsafe archive member path')
    require(path.parts[0] == stage, 'archive member outside expected release directory')
    return clean


def extract_binary(archive: Path, stage: str, binary_name: str, destination: Path) -> None:
    expected = f'{stage}/{binary_name}'
    seen, selected = set(), None
    with (zipfile.ZipFile(archive) if archive.suffix == '.zip' else tarfile.open(archive, 'r:gz')) as handle:
        is_zip = isinstance(handle, zipfile.ZipFile)
        members = handle.infolist() if is_zip else handle.getmembers()
        for member in members:
            name = member_name(member.filename if is_zip else member.name, stage)
            require(name not in seen, 'duplicate archive member')
            seen.add(name)
            if is_zip:
                kind = stat.S_IFMT(member.external_attr >> 16)
                regular = not member.is_dir() and kind in (0, stat.S_IFREG)
                require(regular or (member.is_dir() and kind in (0, stat.S_IFDIR)),
                        'archive contains a nonregular member')
            else:
                regular = member.isfile()
                require(regular or member.isdir(), 'archive contains a nonregular member')
            if name == expected:
                require(regular, 'expected executable is not a regular file')
                selected = member
        require(selected is not None, 'expected executable is missing from archive')
        # Read one validated member into a caller-owned fresh path. Never extractall.
        with (handle.open(selected) if is_zip else handle.extractfile(selected)) as source:
            with destination.open('xb') as output:
                shutil.copyfileobj(source, output)
    require(destination.stat().st_size > 0, 'extracted executable is empty')


def command(args: list[str], prefix: Path) -> None:
    with Path(str(prefix) + '.stdout').open('wb') as stdout, Path(str(prefix) + '.stderr').open('wb') as stderr:
        result = subprocess.run(args, stdout=stdout, stderr=stderr, check=False)
    Path(str(prefix) + '.command.json').write_text(json.dumps(
        {'args': args, 'exitCode': result.returncode}, indent=2) + '\n')
    require(result.returncode == 0, f'{args[0]} failed; see {prefix}.stderr')


def verify_archive(archive: Path, repository: str, tag: str, source_sha: str,
                   prefix: Path) -> dict:
    before = digest(archive)
    signature, certificate = Path(str(archive) + '.sig'), Path(str(archive) + '.pem')
    require(all(path.is_file() and not path.is_symlink() and path.stat().st_size > 0
                for path in (archive, signature, certificate)), 'archive signing material is missing')
    identity = f'https://github.com/{repository}/.github/workflows/release-binaries.yml@refs/tags/{tag}'
    try:
        command(['cosign', 'verify-blob', '--signature', str(signature), '--certificate', str(certificate),
                 '--certificate-identity', identity,
                 '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                 '--certificate-github-workflow-sha', source_sha,
                 '--certificate-github-workflow-repository', repository,
                 '--certificate-github-workflow-ref', f'refs/tags/{tag}', str(archive)], prefix)
    except ValueError:
        # Preserve refused bytes with the retained verifier output for reproduction.
        shutil.copyfile(archive, prefix.parent / (archive.name + '.refused-input'))
        raise
    require(digest(archive) == before, 'archive changed during signature verification')
    return {'archiveSha256': before, 'signatureSha256': digest(signature),
            'certificateSha256': digest(certificate), 'certificateIdentity': identity,
            'oidcIssuer': 'https://token.actions.githubusercontent.com', 'sourceCommit': source_sha}


def verify_source_tree(root: Path, source_sha: str) -> None:
    result = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=False)
    require(result.returncode == 0 and result.stdout.strip() == source_sha,
            'selected source tree differs from signed source commit')
    status = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=all'],
                            capture_output=True, text=True, check=False)
    require(status.returncode == 0 and not status.stdout.strip(),
            'selected source tree contains uncommitted inputs')


def rescan(assets: Path, root: Path, output: Path, work: Path,
           repository: str, tag: str, source_sha: str) -> dict:
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) is not None,
            'invalid repository identity')
    require(re.fullmatch(r'[0-9a-f]{40}', source_sha) is not None, 'invalid source commit')
    require(tag.startswith('v'), 'expected version tag')
    version = tag[1:]
    verify_source_tree(root, source_sha)
    # Source identity also checks the requested version, prior to processing archives.
    GATE.expected_packages(root, version)
    require(not work.exists(), 'archive work directory must be fresh')
    require(not output.exists(), 'rescan output directory must be fresh')
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    expected_archives = {f'chio-{version}-{target}.' + ('zip' if target.endswith('msvc') else 'tar.gz')
                         for target in TARGETS}
    actual_archives = {path.name for path in assets.iterdir()
                       if path.name.endswith(('.tar.gz', '.zip'))}
    require(actual_archives == expected_archives, 'release archive target set is incomplete or unexpected')
    records = []
    for target in TARGETS:
        stage = f'chio-{version}-{target}'
        name = stage + ('.zip' if target.endswith('msvc') else '.tar.gz')
        local = work / target
        local.mkdir()
        archive = local / name
        # Freeze a private copy of the exact signed input before any parser reads it.
        for suffix in ('', '.sig', '.pem'):
            source = assets / (name + suffix)
            require(source.is_file() and not source.is_symlink(), 'missing or symlinked release input')
            shutil.copyfile(source, local / (name + suffix))
        for suffix in ('.sig', '.pem'):
            shutil.copyfile(Path(str(archive) + suffix), output / (name + suffix))
        (output / (target + '.input.json')).write_text(json.dumps(
            {'archiveName': name, 'archiveSha256': digest(archive),
             'sourceCommit': source_sha, 'authenticated': False}, indent=2) + '\n')
        record = verify_archive(archive, repository, tag, source_sha, output / (target + '.cosign'))
        binary = local / ('chio.exe' if target.endswith('msvc') else 'chio')
        extract_binary(archive, stage, binary.name, binary)
        require(digest(archive) == record['archiveSha256'], 'archive changed during extraction')
        sbom = output / (target + '.binary.cdx.json')
        command(['syft', '--config', str(root / 'deploy/sbom/syft.yaml'),
                 '-o', 'cyclonedx-json@1.6=' + str(sbom), 'file:' + str(binary)],
                output / (target + '.syft'))
        document = json.loads(sbom.read_text(), object_pairs_hook=GATE.object_pairs)
        validation = GATE.validate(document, binary, root, version)
        validation['sbomSha256'] = digest(sbom)
        (output / (target + '.validation.json')).write_text(json.dumps(validation, indent=2) + '\n')
        record.update(target=target, archiveName=name, binarySha256=digest(binary), sbomSha256=digest(sbom))
        records.append(record)
    result = {'schema': 'chio.authenticated-release-sbom-rescan.v1', 'passed': True,
              'repository': repository, 'tag': tag, 'sourceCommit': source_sha, 'archives': records,
              'scope': 'Authenticated archive bytes and extracted Rust inventory. SLSA, native-library qualification and host acceptance remain separate gates.'}
    (output / 'authenticated-rescan.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'root', 'output', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('repository', 'tag', 'source-sha'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        result = rescan(args.assets, args.root, args.output, args.work,
                        args.repository, args.tag, args.source_sha)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f'Release SBOM rescan refused: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
