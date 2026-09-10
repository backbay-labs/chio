#!/usr/bin/env python3
"""Copy reviewed text evidence losslessly; never run archived host drivers."""
import argparse
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re


def sha(body):
    return hashlib.sha256(body).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', action='append', required=True, help='GROUP=absolute-directory')
args = parser.parse_args()
out = Path(__file__).resolve().parent
manifest_path = out / 'files.json'
inputs_path = out / 'source-inputs.json'
manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else []
inputs = json.loads(inputs_path.read_text()) if inputs_path.exists() else {'scope': 'Byte-preserved bounded observations, including failures. No host acceptance or publication.', 'groups': []}
by_path = {entry['path']: entry for entry in manifest}
assert len(by_path) == len(manifest)
groups = {entry['group']: entry for entry in inputs['groups']}
scanner = Path('/tmp/chio-root-evidence-scan-20260909.py')
namespace = {}
prefix = scanner.read_text().split('files = 0\n')[0]
assert prefix != scanner.read_text()
exec(compile(prefix, '<credential-collector-prefix-only>', 'exec'), namespace)
secret_values = namespace['secrets']
blocked_names = {'operator.json', 'gateway.json', 'prepare.json', 'auth.json', 'capture.private.json'}
sources = []
for specification in args.source:
    group, directory = specification.split('=', 1)
    assert re.fullmatch('[a-z0-9][a-z0-9-]*', group), group
    source = Path(directory)
    assert source.is_absolute() and source.is_dir() and not source.is_symlink()
    records = []
    for path in sorted(source.rglob('*')):
        assert not path.is_symlink(), str(path)
        if not path.is_file():
            continue
        assert path.name not in blocked_names, str(path)
        assert path.suffix not in {'.db', '.sqlite', '.sqlite3', '.tgz', '.whl', '.so', '.dylib', '.pyc'}, str(path)
        body = path.read_bytes()
        assert b'\0' not in body, str(path)
        body.decode('utf-8')
        assert not any(secret in body for secret in secret_values), 'Credential match; source withheld: ' + str(path)
        assert not re.search(rb'\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}', body), 'Potential provider credential; source withheld: ' + str(path)
        relative = str(path.relative_to(source))
        target = 'raw/' + group + '/' + relative + '.gz'
        compressed = gzip.compress(body, mtime=0)
        record = {'path': target, 'sha256': sha(compressed), 'originalSha256': sha(body), 'originalBytes': len(body), 'source': str(path)}
        if target in by_path:
            assert record == by_path[target], 'Previously archived source changed: ' + str(path)
            assert (out / target).read_bytes() == compressed
        else:
            destination = out / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            assert not destination.exists(), target
            destination.write_bytes(compressed)
            by_path[target] = record
        records.append(record)
    input_record = {'group': group, 'sourceDirectory': str(source), 'files': len(records), 'originalBytes': sum(record['originalBytes'] for record in records), 'inventorySha256': sha(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()), 'archivedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if group in groups:
        previous = groups[group]
        assert {key: value for key, value in input_record.items() if key != 'archivedAt'} == {key: value for key, value in previous.items() if key != 'archivedAt'}, group
    else:
        groups[group] = input_record
    sources.append({'group': group, 'files': len(records)})
manifest = sorted(by_path.values(), key=lambda entry: entry['path'])
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
inputs['groups'] = sorted(groups.values(), key=lambda entry: entry['group'])
inputs_path.write_text(json.dumps(inputs, indent=2) + '\n')
report = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'passed': True, 'privateSourcesRead': namespace['sources'], 'distinctSecretValuesCompared': len(secret_values), 'filesScannedThisInvocation': sum(entry['files'] for entry in sources), 'groupsScannedThisInvocation': sources, 'matchingPaths': [], 'scope': 'Known designated operator and provider credential values compared in plaintext before compression, plus provider key shape detection. Public signatures and identity descriptors are retained. Final whole-record scan is separate.'}
(out / 'archival-credential-exclusion.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'groups': sources, 'totalRawFiles': len(manifest), 'credentialMatches': 0}))
