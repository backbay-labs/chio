#!/usr/bin/env python3
"""Read installed bytes after host tests without launching any host or owner."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import zipfile


def sha(body):
    return hashlib.sha256(body).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
out = args.output
out.mkdir(mode=0o700, exist_ok=False)
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest = Path('/tmp/chio-kernel-rc-static-installations-20260910.json')
installations = json.loads(manifest.read_text())
bundle = Path('/Users/connor/.local/share/chio-required-candidates/20260909')
consumers = Path('/tmp/chio-kernel-rc-consumers-20260910')
comparisons = []


def compare_archive(label, archive, package, expected):
    actual = sha(archive.read_bytes())
    assert actual == expected, label + ' archive mismatch'
    entries = []
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if not member.isfile():
                continue
            assert member.name.startswith('package/')
            relative = Path(member.name[len('package/'):])
            assert not relative.is_absolute() and '..' not in relative.parts
            wanted = source.extractfile(member).read()
            target = package / relative
            actual_bytes = target.read_bytes()
            assert wanted == actual_bytes, label + ': ' + str(relative)
            entries.append({'path': str(relative), 'sha256': sha(wanted), 'bytes': len(wanted)})
    entries.sort(key=lambda entry: entry['path'])
    write(out / (label + '-archive-files.json'), entries)
    comparisons.append({
        'label': label, 'archive': str(archive), 'archiveSha256': actual,
        'packageDirectory': str(package), 'resolvedPackageDirectory': str(package.resolve()),
        'regularArchiveFilesMatched': len(entries), 'missing': [], 'mismatched': [],
        'inventory': label + '-archive-files.json',
        'scope': 'Post-run comparison of regular archive members. Extra installed files, links and transitive packages outside the archive are not an archive equality claim.',
    })


for entry in installations:
    compare_archive(entry['host'], Path(entry['archive']), Path(entry['packageDirectory']), entry['sha256'])
compare_archive('hermes-bridge', bundle / 'packages/chio-bridge-hermes-0.3.0-b7785282b4f4.tgz',
                consumers / 'hermes/bridge/node_modules/@chio/bridge',
                'b7785282b4f4e4da42e4158c7390a2d1411ba2763b01956b07896aadf6dcc6d9')
compare_archive('operator-recovery-bridge', bundle / 'packages/chio-bridge-operator-0.3.0-02a0e4ad4e61.tgz',
                bundle / 'install/operator-bridge/node_modules/@chio/bridge',
                '02a0e4ad4e61ffb989302cae8774a9ae9ab8f647473f1926d1e671673169a37b')

lock = consumers / 'pi/consumer/package-lock.json'
lock_entries = [(key, value) for key, value in json.loads(lock.read_text())['packages'].items()
                if key.endswith('/@earendil-works/pi-coding-agent') and 'integrity' in value]
assert lock_entries and len({entry['integrity'] for _, entry in lock_entries}) == 1
integrity = lock_entries[0][1]['integrity']
assert integrity.startswith('sha512-')
hex_digest = base64.b64decode(integrity.split('-', 1)[1]).hex()
cache = consumers / 'pi/empty-cache/_cacache/content-v2/sha512' / hex_digest[:2] / hex_digest[2:4] / hex_digest[4:]
assert hashlib.sha512(cache.read_bytes()).hexdigest() == hex_digest
peer = consumers / 'pi/consumer/node_modules/@earendil-works/pi-coding-agent'
compare_archive('pi-native-peer', cache, peer, sha(cache.read_bytes()))
write(out / 'pi-peer-lock-binding.json', {
    'lock': str(lock), 'lockSha256': sha(lock.read_bytes()), 'matchingEntries': lock_entries,
    'package': json.loads((peer / 'package.json').read_text())['name'],
    'version': json.loads((peer / 'package.json').read_text())['version'], 'integrity': integrity,
    'scope': 'Current lock and cached public registry tarball corroboration. No new download, install or historical startup check is claimed.',
})

wheel = bundle / 'hermes-wheelhouse/chio_hermes-0.1.2-py3-none-any.whl'
assert sha(wheel.read_bytes()) == '625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818'
sites = list((consumers / 'hermes/consumer/lib').glob('python*/site-packages'))
assert len(sites) == 1
wheel_entries = []
with zipfile.ZipFile(wheel) as source:
    for name in source.namelist():
        if not name.startswith('chio_hermes/') or name.endswith('/'):
            continue
        body = source.read(name)
        assert (sites[0] / name).read_bytes() == body, name
        wheel_entries.append({'path': name, 'sha256': sha(body), 'bytes': len(body)})
write(out / 'hermes-wheel-files.json', wheel_entries)

host_identity_path = Path('/tmp/chio-hermes-public-final-install-20260910/identity.json')
host_identity = json.loads(host_identity_path.read_text())
host_source = Path(host_identity['sourceDirectory'])
current_commit = git(host_source, 'rev-parse', 'HEAD')
current_tree = git(host_source, 'rev-parse', 'HEAD^{tree}')
tracked_diff = git(host_source, 'diff', 'HEAD', '--')
assert current_commit == host_identity['sourceCommit']
assert current_tree == host_identity['sourceTree'] and tracked_diff == ''
assert sha((host_source / 'uv.lock').read_bytes()) == host_identity['lockSha256']
assert sha((host_source / 'pyproject.toml').read_bytes()) == host_identity['pyprojectSha256']
host_source_record = {
    'sourceDirectory': str(host_source), 'recordedIdentity': str(host_identity_path),
    'recordedIdentitySha256': sha(host_identity_path.read_bytes()),
    'expectedCommit': host_identity['sourceCommit'], 'currentCommit': current_commit,
    'expectedTree': host_identity['sourceTree'], 'currentTree': current_tree,
    'trackedDiffEmpty': True, 'untrackedPaths': git(host_source, 'ls-files', '--others', '--exclude-standard').splitlines(),
    'lockSha256': host_identity['lockSha256'], 'pyprojectSha256': host_identity['pyprojectSha256'],
    'scope': 'Post-run Git HEAD, tree, tracked diff and two named source hashes. Untracked files and all interpreter dependencies are not recursively attested.',
}
write(out / 'hermes-host-source.json', host_source_record)

initial = Path('/tmp/chio-static-live-expiry-mac-hosts-20260910')
identity = json.loads((initial / 'identity.json').read_text())
codex_launch = json.loads((initial / 'codex/case/in-flight-expiry/launch.json').read_text())
claude_identity = json.loads(Path('/tmp/chio-kernel-rc-static-matrix-20260910/claude/useful/identity.json').read_text())
binaries = []
for label, path, expected in [
    ('kernel', Path(identity['kernel']), identity['kernelSha256']),
    ('codex', Path(codex_launch['boundary']['codex']), codex_launch['host_binary_sha256']),
    ('claude', Path(claude_identity['host']), claude_identity['hostSha256']),
    ('hermes-python', Path(host_identity['hostPython']), host_identity['pythonBinarySha256']),
]:
    actual = sha(path.read_bytes())
    assert actual == expected, label
    binaries.append({'label': label, 'path': str(path), 'resolvedPath': str(path.resolve()), 'sha256': actual, 'expectedSha256': expected, 'matches': True})

source_snapshots = []
for index, (path, expected) in enumerate(identity['sourceHashes'].items()):
    snapshot = initial / 'source-snapshots' / (str(index) + '-' + Path(path).name)
    assert sha(snapshot.read_bytes()) == expected
    current = sha(Path(path).read_bytes())
    source_snapshots.append({'source': path, 'snapshot': str(snapshot), 'snapshotSha256': expected, 'currentSha256': current, 'currentMatchesHistoricalSnapshot': current == expected})

write(out / 'post-run-provenance.json', {
    'startedAt': started, 'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'scope': 'Read-only post-run observations. These checks do not establish original pre-run or continuous runtime identity.',
    'installationManifest': str(manifest), 'installationManifestSha256': sha(manifest.read_bytes()),
    'archiveComparisons': comparisons,
    'hermesWheel': {'path': str(wheel), 'sha256': sha(wheel.read_bytes()), 'adapterFilesMatched': len(wheel_entries), 'scope': 'Only chio_hermes regular package files; wheel metadata and all interpreter dependencies excluded.'},
    'nativeBinaryComparisons': binaries, 'initialSourceSnapshots': source_snapshots,
    'initialSourceInputsRecordedUnchanged': json.loads((initial / 'results.json').read_text())['sourceInputsUnchanged'],
    'openclawImage': {'recordedImage': identity['openclawImage'], 'reinspected': False, 'reason': 'This archival task performs no Docker or host operations.'},
    'noHostOrDockerLaunchDuringReview': True, 'acceptedHosts': 0,
})
(out / 'review-installed.py').write_bytes(Path(__file__).read_bytes())
(out / 'installation-manifest.json').write_bytes(manifest.read_bytes())
print(json.dumps({'archiveComparisons': len(comparisons), 'archiveFilesMatched': sum(entry['regularArchiveFilesMatched'] for entry in comparisons), 'hermesAdapterFilesMatched': len(wheel_entries), 'nativeBinaryMatches': len(binaries), 'sourceSnapshots': len(source_snapshots), 'currentSourceDifferences': sum(not entry['currentMatchesHistoricalSnapshot'] for entry in source_snapshots), 'output': str(out)}))
