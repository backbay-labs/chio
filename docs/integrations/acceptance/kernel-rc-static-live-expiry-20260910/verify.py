#!/usr/bin/env python3
"""Verify the archived bytes and bounded assertions without running a host."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def sha(body):
    return hashlib.sha256(body).hexdigest()


def raw(group, relative):
    return gzip.decompress((ROOT / 'raw' / group / (relative + '.gz')).read_bytes())


def read(group, relative):
    return json.loads(raw(group, relative))


manifest = json.loads((ROOT / 'files.json').read_text())
assert len(manifest) == len({entry['path'] for entry in manifest})
assert {str(path.relative_to(ROOT)) for path in (ROOT / 'raw').rglob('*') if path.is_file()} == {entry['path'] for entry in manifest}
for entry in manifest:
    path = ROOT / entry['path']
    assert not path.is_symlink()
    compressed = path.read_bytes()
    body = gzip.decompress(compressed)
    assert sha(compressed) == entry['sha256'], entry['path']
    assert sha(body) == entry['originalSha256'], entry['path']
    assert len(body) == entry['originalBytes'], entry['path']

inputs = json.loads((ROOT / 'source-inputs.json').read_text())
for group in inputs['groups']:
    prefix = 'raw/' + group['group'] + '/'
    entries = [entry for entry in manifest if entry['path'].startswith(prefix)]
    entries.sort(key=lambda entry: Path(entry['source']))
    assert len(entries) == group['files']
    assert sum(entry['originalBytes'] for entry in entries) == group['originalBytes']
    assert sha(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()) == group['inventorySha256']
    for entry in entries:
        relative = entry['path'][len(prefix):-3]
        assert entry['source'] == str(Path(group['sourceDirectory']) / relative)

checksums = {}
for line in (ROOT / 'SHA256SUMS').read_text().splitlines():
    expected, relative = line.split('  ', 1)
    assert relative not in checksums
    assert sha((ROOT / relative).read_bytes()) == expected, relative
    checksums[relative] = expected
assert {str(path.relative_to(ROOT)) for path in ROOT.rglob('*') if path.is_file() and path.name != 'SHA256SUMS'} == set(checksums)

KERNEL = 'c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e'
successful = [('original-mac-hosts', 'codex'), ('mac-hosts-r2', 'pi'), ('mac-hosts-r2', 'hermes'), ('openclaw-r2', 'openclaw')]
failed = [('original-mac-hosts', 'pi'), ('original-mac-hosts', 'hermes'), ('original-openclaw', 'openclaw')]
batches = sorted({group for group, _ in successful + failed})
for group in batches:
    identity = read(group, 'identity.json')
    assert identity['kernelSha256'] == KERNEL
    assert identity['kernelSource'] == 'bafa02b06de93553cecb6f60b340f3dd8fd9b401'
    result = read(group, 'results.json')
    assert result['sourceInputsUnchanged'] is True
    for index, (source, expected) in enumerate(identity['sourceHashes'].items()):
        assert sha(raw(group, 'source-snapshots/' + str(index) + '-' + Path(source).name)) == expected
    if group != 'original-mac-hosts':
        assert raw(group, 'installed-identities-before.json') == raw(group, 'installed-identities-after.json')

for group, host in successful + failed:
    result = next(entry for entry in read(group, 'results.json')['hosts'] if entry['host'] == host)
    assert result['passed'] is ((group, host) in successful)
    assert result['originalStateRetained'] is True
    prefix = host + '/case/'
    binding = read(group, prefix + 'live-expiry-binding.json')
    credential = binding['sessionCredential']
    capability = binding['capability']
    assert credential['expiresAt'] == capability['expires_at']
    assert capability['expires_at'] - capability['issued_at'] == read(group, 'identity.json')['capabilityTtl']
    assert credential['capabilityIds'] == [capability['id']]
    assert credential['subjectKey'] == capability['subject']
    assert binding['credentialRequestedTtlSeconds'] == 900
    events = [json.loads(line) for line in raw(group, prefix + 'expiry-cutpoint.jsonl').splitlines()]
    first = next(entry for entry in events if entry['event'] == 'native-request' and entry['index'] == 1)
    held = next(entry for entry in events if entry['event'] == 'native-request' and entry['index'] == 2)
    released = next(entry for entry in events if entry['event'] == 'released-to-kernel' and entry['index'] == 2)
    first_response = next(entry for entry in events if entry['event'] == 'kernel-response' and entry['index'] == 1)
    response = next(entry for entry in events if entry['event'] == 'kernel-response' and entry['index'] == 2)
    assert len(events) == 5
    assert first['callerHeaderMatches'] is True and held['callerHeaderMatches'] is True
    assert held['firstSucceeded'] is True
    assert held['capabilityId'] == capability['id']
    assert held['subjectKey'] == capability['subject']
    assert held['sessionId'] == credential['sessionId']
    assert held['capabilityExpiresAt'] == held['credentialExpiresAt'] == capability['expires_at']
    assert first_response['receivedAtMs'] < capability['expires_at'] * 1000
    assert held['heldAtMs'] < capability['expires_at'] * 1000 <= released['releasedAtMs'] <= response['receivedAtMs']
    assert released['originalTransportUnchanged'] is True
    for field in ['requestId', 'requestBodySha256', 'method', 'protocolVersion', 'tool', 'arguments', 'sessionId', 'subjectKey', 'capabilityId', 'capabilityExpiresAt', 'credentialExpiresAt']:
        assert held[field] == released[field] == response[field], (group, host, field)
    assert all(not entry['signalAborted'] for entry in events)
    assert first_response['status'] == 200 and response['status'] == 401
    assert sha(response['body'].encode()) == response['bodySha256']
    before = read(group, prefix + 'in-flight-expiry/before.json')
    after = read(group, prefix + 'in-flight-expiry/after.json')
    assert before['dispatch'] == []
    assert len(after['dispatch']) - len(before['dispatch']) == 1
    assert after['dispatch'][0]['argumentsSha256'] == sha(json.dumps(first['arguments'], sort_keys=True, separators=(',', ':')).encode())
    remote_path = first['arguments']['path']
    assert held['arguments']['path'] == remote_path
    assert after['files'][remote_path.removeprefix('/workspace/')] == first['arguments']['content']
    assert first['arguments']['content'] != held['arguments']['content']
    for name, value in before['files'].items():
        assert after['files'][name] == value
    native = read(group, prefix + 'in-flight-expiry/native-dispatch.json')
    assert native['attemptCount'] == 2 and native['expectedAttemptObserved'] is True
    assert len(native['calls']) == 2 and len(set(native['returnedToolCallIds'])) == 2
    assert {entry['id'] for entry in native['calls']} == set(native['returnedToolCallIds'])
    for call, transported in zip(native['calls'], [first, held]):
        native_arguments = call['arguments']
        if call['name'] in {'chio_execute', 'chio_call'}:
            assert native_arguments['tool'] == transported['tool']
            native_arguments = native_arguments['arguments']
        assert native_arguments == transported['arguments']
    commands = read(group, host + '/commands.json')
    case_command = next(entry for entry in commands if entry['label'] == 'in-flight-expiry')
    assert case_command['timedOut'] is False
    if (group, host) in failed:
        assert case_command['exitCode'] != 0
        assert read(group, prefix + 'failure.json')['claim'] == 'unresolved; never counted as acceptance'
        assert not any(entry['path'] == 'raw/' + group + '/' + prefix + 'in-flight-expiry-result.json.gz' for entry in manifest)
        stop = read(group, host + '/post-failure-stop.json')
        assert stop['exitCode'] == 0 and 'retained' in stop['claim']
        continue
    assert case_command['exitCode'] == 0
    stop = next(entry for entry in commands if entry['label'] == 'stop')
    assert stop['exitCode'] == 0 and stop['timedOut'] is False
    case = read(group, prefix + 'in-flight-expiry-result.json')
    assert case['passed'] is True and case['realNativeCalls'] == 2
    assert case['positiveResourceDispatches'] == 1 and case['expiredRequestDispatches'] == 0
    assert case['sameActualRequestReachedKernel'] is True and case['kernelHttpStatus'] == 401
    assert case['clientSignalAborted'] is False and case['expiredResultAcknowledged'] is False
    assert case['originalAuthorityUnchanged'] is True
    states = read(group, prefix + 'journal-states.json')
    assert len(states) == 2
    positive = next(entry for entry in states if entry['requestId'] == first['requestId'])
    expired = next(entry for entry in states if entry['requestId'] == held['requestId'])
    assert positive['state'] == 'completed' and positive['acknowledged'] is True and positive['hostDeliveryConfirmed'] is True
    assert expired['state'] == 'unknown' and expired['acknowledged'] is False
    assert expired['outcome']['state'] == 'unknown' and expired['outcome']['evidence'] == 'unverified'
    outcome = read(group, prefix + 'native-expiry-outcome.json')
    assert outcome['requestId'] == held['requestId']
    assert outcome['toolCallId'] == native['calls'][1]['id']
    if host == 'pi':
        assert outcome['nativeToolError'] is True and outcome['nativeCarriesRequestId'] is False
        assert outcome['nativeMessage'] == 'Gateway reports an unknown external outcome'
    if host == 'openclaw':
        assert outcome['nativeToolError'] is False and outcome['nativeCarriesKernelRequestId'] is False
        assert outcome['nativeOutcome']['state'] == 'unknown' and outcome['nativeOutcome']['evidence'] == 'unverified'
        context = read(group, prefix + 'openclaw-identity-binding.json')
        observed = [json.loads(line) for line in raw(group, prefix + 'openclaw-gateway-session.jsonl').splitlines()]
        assert len(observed) == 1 and observed == context['gatewaySessions']
        mapping = outcome['identityMapping']
        assert mapping['gatewayHttpSession'] == observed[0]
        assert observed[0]['observedAtMs'] < first['heldAtMs']
        assert mapping['gatewayNamespace'] == context['gatewayNamespace']
        assert context['launch']['sessionId'] == context['agentMeta']['sessionId'] == context['systemPromptReport']['sessionId']
        assert context['launch']['gatewayConfigSha256'] == context['configurationSha256'] == binding['configurationSha256']
        assert context['launch']['kernelAuthority']['sessionId'] == credential['sessionId']
        assert context['launch']['kernelAuthority']['capabilityId'] == capability['id']
        assert mapping['caller'] == {'host': 'openclaw', 'agentId': 'main', 'sessionId': context['launch']['sessionId'], 'sessionKey': context['systemPromptReport']['sessionKey']}
        for call, request, ids in zip(native['calls'], [first, held], mapping['calls']):
            guest_id = sha(json.dumps({'caller': mapping['caller'], 'toolCallId': call['id']}, sort_keys=True, separators=(',', ':')).encode())
            rpc_id = observed[0]['sessionId'] + ':' + json.dumps(guest_id, separators=(',', ':'))
            kernel_id = mapping['gatewayNamespace'] + ':' + sha(json.dumps({'id': rpc_id}, separators=(',', ':')).encode())
            assert ids == {'toolCallId': call['id'], 'guestRequestId': guest_id, 'kernelRequestId': kernel_id}
            assert kernel_id == request['requestId']
        assert outcome['nativeOutcome']['requestId'] == mapping['calls'][1]['guestRequestId']

review = read('post-run-installed-review', 'post-run-provenance.json')
assert review['noHostOrDockerLaunchDuringReview'] is True and review['acceptedHosts'] == 0
assert len(review['archiveComparisons']) == 7
assert sum(entry['regularArchiveFilesMatched'] for entry in review['archiveComparisons']) == 8893
assert review['hermesWheel']['adapterFilesMatched'] == 18
assert len(review['nativeBinaryComparisons']) == 4 and all(entry['matches'] for entry in review['nativeBinaryComparisons'])
for entry in review['archiveComparisons']:
    inventory = read('post-run-installed-review', entry['inventory'])
    assert len(inventory) == entry['regularArchiveFilesMatched']

controls = read('binding-repair-controls', 'controls-result.json')
assert controls['exitCode'] == 0
assert b'Ran 25 tests' in raw('binding-repair-controls', 'controls.stderr')
original_mapping = read('binding-repair-controls', 'source-and-original-guest-binding.json')
assert original_mapping['fullKernelIdMapping'] is False
for entry in manifest:
    prefix = 'raw/binding-repair-controls/'
    if entry['path'].startswith(prefix):
        relative = entry['path'][len(prefix):-3]
        assert raw('binding-repair-controls', relative) == raw('binding-repair-followup', relative)
session_audit = read('binding-repair-followup', 'public-session-observation-audit.json')
assert session_audit['passed'] is True and session_audit['matchingPaths'] == []
assert set(session_audit['observedFields']) == {'event', 'sessionId', 'localPort', 'method', 'path', 'status', 'observedAtMs'}
for entry in session_audit['scanFiles']:
    assert sha(raw('openclaw-r2', 'openclaw/case/' + Path(entry['path']).name)) == entry['sha256']

assert raw('validation', 'product-copy.stdout') == b'OK Proof Room release truth\n'
assert raw('final-copy-check', 'product-copy.stdout') == b'OK Proof Room release truth\n'
assert read('final-copy-check', 'command.json')['exitCode'] == 0
assert b'release truth positives and negatives passed' in raw('validation', 'product-copy-regressions.stdout')
for entry in read('validation', 'commands.json'):
    assert entry['exitCode'] == 0
credential_scan = json.loads((ROOT / 'credential-exclusion.json').read_text())
assert credential_scan['passed'] is True and not credential_scan['matchingPaths']
print(json.dumps({'passed': True, 'rawFiles': len(manifest), 'checksums': len(checksums), 'successfulBoundedHostCases': len(successful), 'originalFailedHostCasesRetained': len(failed), 'acceptedHosts': 0}))
