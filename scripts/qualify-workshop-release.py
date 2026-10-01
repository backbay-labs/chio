#!/usr/bin/env python3
"""Run an installed CLI/operator pair through the retained workshop journey.

The public result contains identities and checks only. Connection credentials,
native account files, private paths, and raw native responses stay local.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


class Host:
    def __init__(self, cli, root, setup, log, workspace=None):
        arguments = [str(cli), 'megastart', 'workshop', '--no-open']
        arguments += ['--workspace', str(workspace)] if workspace else ['--setup', setup]
        self.process = subprocess.Popen(arguments, env={**os.environ, 'CHIO_WORKSHOPS': str(root)}, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('The installed workshop exited before opening; inspect the private host log')
            descriptors = list(root.glob('*/connections/console.json'))
            if descriptors:
                self.workspace = descriptors[0].parent.parent
                descriptor = json.loads(descriptors[0].read_text())
                if descriptor['pid'] == self.process.pid:
                    self.base = descriptor['endpoint']
                    self.token = descriptor['token']
                    self.state = self.get('state')
                    return
            time.sleep(.05)
        self.stop()
        raise RuntimeError('The installed workshop did not become ready')

    def request(self, path, body=None, authenticated=True):
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(self.base + '/api/workshop/v1/' + path, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status, raw = response.status, response.read(2_000_001)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(2_000_001)
        if len(raw) > 2_000_000:
            raise RuntimeError('Host exceeded the response bound')
        return status, json.loads(raw)

    def get(self, path):
        status, value = self.request(path)
        if status != 200:
            raise RuntimeError(f'Host read failed: {status} {value.get("error", {}).get("code")}')
        return value

    def intent(self, command, state=None):
        state = state or self.get('state')
        mission = state.get('mission') or {}
        return {'schema_version': 1, 'request_id': str(uuid.uuid4()), 'workspace_id': state['workspace']['id'],
                'mission_id': mission.get('id'), 'expected': {'host_epoch': state['host']['epoch'],
                'mission_input_identity': mission.get('input_identity'), 'candidate_digest': command.get('candidate_digest')},
                'command': command}

    def run(self, intent, timeout):
        status, accepted = self.request('commands', intent)
        if status != 202:
            raise RuntimeError(f'Command refused: {status} {accepted.get("error", {}).get("code")}')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            observation = self.get('commands/' + intent['request_id'])
            if observation['status'] not in ['accepted', 'running']:
                if observation['status'] != 'succeeded':
                    raise RuntimeError(f'Command {intent["command"]["type"]} ended {observation["status"]}; inspect the private log')
                return observation
            time.sleep(.15)
        raise RuntimeError('Command qualification deadline exceeded; inspect retained work before retrying')

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--setup', default='sf1.reference')
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    cli = args.cli.resolve(strict=True)
    operator = cli.with_name('megastart')
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    root = args.output / 'workspaces'
    evidence = {'schemaVersion': 1, 'setup': args.setup, 'cliSha256': sha(cli), 'operatorSha256': sha(operator),
                'checks': {}, 'passed': False, 'published': False}
    host = None
    log_path = args.output / 'host.log'
    log_path.touch(mode=0o600)
    try:
        with log_path.open('a') as log:
            evidence['cliVersionOutput'] = subprocess.check_output([str(cli), '--version'], text=True).strip()
            evidence['pairContract'] = subprocess.check_output([str(cli), 'megastart', 'workshop-version'], text=True).strip()
            host = Host(cli, root, args.setup, log)
            initial = host.get('state')
            assert initial['mission'] is None and initial['workspace']['missions'] == []
            evidence['checks']['importDoesNotExecute'] = True
            assert host.request('state', authenticated=False)[0] == 401
            evidence['checks']['authenticationRequired'] = True
            evidence['uiBuildId'] = initial['host']['ui_build_id']
            evidence['setupImported'] = initial['workspace']['setup']
            blockers = [c['id'] for c in initial['readiness'] if c['blocking'] and c['status'] != 'ready']
            if blockers:
                raise RuntimeError('Missing preparation: ' + ', '.join(blockers))
            host.run(host.intent({'type': 'initialize', 'setup': initial['workspace']['setup']}), args.timeout)
            run = host.intent({'type': 'run'})
            host.run(run, args.timeout)
            host.run(run, args.timeout)
            result = host.get('state')
            mission = result['mission']
            assert mission['phase'] == 'awaiting_review' and mission['publication'] is None
            assert mission['tests']['status'] == 'passed' and len(mission['tests']['checks']) == 5
            evidence['checks']['actualBaselineFiveChecks'] = True
            evidence['checks']['repeatedRequestDeduplicated'] = True
            wrong = host.intent({'type': 'approve', 'candidate_digest': 'f' * 64})
            assert host.request('commands', wrong)[0] == 409
            evidence['checks']['staleApprovalRejected'] = True
            host.run(host.intent({'type': 'approve', 'candidate_digest': mission['proposal']['candidate_digest']}), args.timeout)
            published = host.get('state')['mission']
            assert published['phase'] == 'published' and published['publication']['candidate_digest'] == mission['proposal']['candidate_digest']
            evidence['checks']['exactLocalPublication'] = True
            parent = host.workspace / 'missions' / published['id']
            before = tree(parent)
            revision = host.intent({'type': 'create_revision', 'recipe': 'singleton-window-v1'})
            child_id = host.run(revision, args.timeout)['result_mission_id']
            assert host.run(revision, args.timeout)['result_mission_id'] == child_id
            child = host.get('state')['mission']
            assert child['id'] != published['id'] and child['harness_digest'] != published['harness_digest']
            assert child['source_digest'] == published['source_digest']
            host.run(host.intent({'type': 'run'}), args.timeout)
            six = host.get('state')['mission']
            assert six['tests']['status'] == 'passed' and len(six['tests']['checks']) == 6
            assert any(c['name'] == 'singleton_window_preserves_value' and c['status'] == 'passed' for c in six['tests']['checks'])
            assert before == tree(parent)
            evidence['checks']['freshChildSixChecks'] = True
            evidence['checks']['parentBytesPreserved'] = True
            evidence['checks']['revisionRequestDeduplicated'] = True
            evidence['baseline'] = {k: published[k] for k in ['id', 'input_identity', 'source_digest', 'harness_digest']}
            evidence['child'] = {k: six[k] for k in ['id', 'input_identity', 'source_digest', 'harness_digest']}
            evidence['candidateDigest'] = six['proposal']['candidate_digest']
            workspace = host.workspace
            old_epoch = host.get('state')['host']['epoch']
            host.stop()
            host = Host(cli, root, args.setup, log, workspace)
            resumed = host.get('state')
            assert resumed['host']['epoch'] != old_epoch and resumed['mission']['id'] == child_id
            assert host.get('state?mission=' + published['id'])['mission']['phase'] == 'published'
            assert before == tree(parent)
            evidence['checks']['reopenRetainsHistory'] = True
            evidence['passed'] = True
    except Exception as error:
        evidence['failure'] = str(error)
        raise
    finally:
        if host:
            host.stop()
        (args.output / 'qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(f'PASS: installed {args.setup} baseline, publication, sixth check, deduplication and reopen')


if __name__ == '__main__':
    main()
