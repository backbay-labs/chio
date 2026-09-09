#!/usr/bin/env python3
"""Compare real MCP session startup on one isolated durable resource history."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixed-kernel', required=True)
    parser.add_argument('--baseline-kernel', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--calls', type=int, default=128)
    parser.add_argument('--max-startup-seconds', type=float, default=10)
    args = parser.parse_args()
    state = Path(args.state_dir).resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    volume = 'chio-required-startup-' + uuid.uuid4().hex[:12]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    token, admin = secrets.token_hex(32), secrets.token_hex(32)
    with os.fdopen(os.open(state / 'operator-private.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as private:
        json.dump({'agentToken': token, 'adminToken': admin, 'port': port}, private)
        private.flush()
        os.fsync(private.fileno())
    env = dict(os.environ, CHIO_AUTH_TOKEN=token, CHIO_ADMIN_TOKEN=admin)
    endpoint = f'http://127.0.0.1:{port}/mcp'
    report = {'schema': 'chio.session-startup-regression.v1', 'volume': volume,
              'calls': args.calls, 'environment': platform.platform(), 'maxStartupSeconds': args.max_startup_seconds, 'artifacts': {name: {'path': path, 'sha256': sha(path)} for name, path in [('fixed', args.fixed_kernel), ('baseline', args.baseline_kernel)]},
              'policySha256': sha(args.policy), 'image': args.image, 'events': []}
    def save():
        (state / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    def docker(*rest):
        return subprocess.run(['docker', *rest], check=True, capture_output=True, text=True).stdout
    docker('volume', 'create', '--label', 'chio.task=session-startup-regression', volume)
    docker('run', '--rm', '--network', 'none', '--user', '0', '--mount', f'type=volume,src={volume},dst=/workspace', '--entrypoint', 'node', args.image, '-e', "require('fs').chownSync('/workspace',1000,1000)")
    wrapped = ['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', f'type=volume,src={volume},dst=/workspace', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', args.image]
    common = ['--session-db', str(state / 'sessions.sqlite'), '--receipt-db', str(state / 'receipts.sqlite'), '--authority-db', str(state / 'authority.sqlite'), 'mcp', 'serve-http', '--policy', str(Path(args.policy).resolve()), '--server-id', 'fs', '--shared-hosted-owner', '--listen', f'127.0.0.1:{port}', '--', *wrapped]
    child = None
    def start(binary, label):
        nonlocal child
        log = open(state / (label + '.log'), 'ab')
        child = subprocess.Popen([binary, *common], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        log.close()
        for _ in range(100):
            if child.poll() is not None:
                raise RuntimeError(f'{label} exited during startup')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    return
            except OSError:
                time.sleep(.1)
        raise RuntimeError(f'{label} did not listen')
    def stop():
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
        child = None
    def rpc(method, params=None, session=None, notification=False, timeout=30):
        request = {'jsonrpc': '2.0', 'method': method}
        if not notification:
            request['id'] = uuid.uuid4().hex
        if params is not None:
            request['params'] = params
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json', 'MCP-Protocol-Version': '2025-11-25'}
        if session:
            headers['MCP-Session-Id'] = session
        started = time.perf_counter()
        with urllib.request.urlopen(urllib.request.Request(endpoint, json.dumps(request).encode(), headers), timeout=timeout) as response:
            raw = response.read().decode()
            if any(line.startswith('data:') for line in raw.splitlines()):
                raw = '\n'.join(line[5:].strip() for line in raw.splitlines() if line.startswith('data:'))
            try:
                data = json.loads(raw) if raw and not notification else None
            except json.JSONDecodeError:
                (state / ('invalid-' + method.replace('/', '-') + '.txt')).write_text(raw)
                raise
            if data and 'error' in data:
                raise RuntimeError(json.dumps(data['error']))
            return data, response.headers.get('MCP-Session-Id'), time.perf_counter() - started
    def session(label):
        result, session_id, elapsed = rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'chio-session-startup-regression', 'version': '1'}})
        if not session_id:
            raise RuntimeError('initialize omitted session identity')
        rpc('notifications/initialized', session=session_id, notification=True)
        context, _, context_elapsed = rpc('chio/execution-context', session=session_id)
        report['events'].append({'case': label, 'initializeSeconds': elapsed, 'contextSeconds': context_elapsed, 'capabilityCount': len(context['result']['capabilityIds'])})
        save()
        return session_id
    try:
        start(args.fixed_kernel, 'seed-fixed')
        active = session('empty-fixed')
        for index in range(args.calls):
            response, _, elapsed = rpc('tools/call', {'name': 'write_file', 'arguments': {'path': f'/workspace/startup-{index:04}.txt', 'content': f'effect {index}\n'}, '_meta': {'chioRequestId': f'startup-seed-{index}'}}, session=active)
            if response['result'].get('isError'):
                raise RuntimeError('seed call denied: ' + json.dumps(response))
            report['events'].append({'case': 'seed', 'index': index, 'seconds': elapsed, 'response': response})
            save()
        stop()
        with sqlite3.connect(state / 'receipts.sqlite') as db:
            report['receiptCount'] = db.execute('select count(*) from chio_tool_receipts').fetchone()[0]
            report['checkpointCount'] = db.execute('select count(*) from kernel_checkpoints').fetchone()[0]
        if report['checkpointCount'] < 1:
            raise RuntimeError('history has no signed checkpoint; regression was not exercised')
        for label, binary in [('baseline', args.baseline_kernel), ('fixed', args.fixed_kernel)]:
            start(binary, label)
            for index in range(3):
                started = time.perf_counter()
                try:
                    session(f'{label}-{index}')
                except Exception as error:
                    report['events'].append({'case': f'{label}-{index}', 'errorType': type(error).__name__, 'error': str(error), 'seconds': time.perf_counter() - started})
                    save()
                    break
            stop()
        observed = docker('run', '--rm', '--network', 'none', '--read-only', '--mount', f'type=volume,src={volume},dst=/workspace,readonly', '--entrypoint', 'node', args.image, '-e', "const f=require('fs'),c=require('crypto');const files=f.readdirSync('/workspace').sort();console.log(JSON.stringify(files.map(n=>({name:n,content:f.readFileSync('/workspace/'+n,'utf8')}))))")
        actual = json.loads(observed)
        expected = [{'name': f'startup-{index:04}.txt', 'content': f'effect {index}\n'} for index in range(args.calls)]
        report['observer'] = {'exactEffectsMatch': actual == expected, 'effects': actual}
        baseline = [event for event in report['events'] if event['case'].startswith('baseline-')]
        fixed = [event for event in report['events'] if event['case'].startswith('fixed-')]
        if baseline and fixed and all('error' not in event for event in fixed):
            baseline_seconds = max(event.get('seconds', event.get('initializeSeconds', 0) + event.get('contextSeconds', 0)) for event in baseline)
            fixed_seconds = max(event['initializeSeconds'] + event['contextSeconds'] for event in fixed)
            report['comparison'] = {'baselineMaxSeconds': baseline_seconds, 'fixedMaxSeconds': fixed_seconds, 'observedRatio': baseline_seconds / fixed_seconds}
        report['passed'] = actual == expected and all('error' not in event and event['initializeSeconds'] + event['contextSeconds'] <= args.max_startup_seconds for event in report['events'] if event['case'].startswith('fixed-')) and len([event for event in report['events'] if event['case'].startswith('fixed-')]) == 3
        save()
        print(json.dumps({'report': str(state / 'report.json'), 'passed': report['passed'], 'startup': [event for event in report['events'] if event['case'] != 'seed']}, indent=2))
    finally:
        stop()
        save()


if __name__ == '__main__':
    main()
