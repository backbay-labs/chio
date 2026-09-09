#!/usr/bin/env python3
"""Separate process readiness from session latency on preserved fixture history."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

p = argparse.ArgumentParser(description=__doc__)
for flag in ('state-dir', 'kernel', 'policy'):
    p.add_argument('--' + flag, required=True)
a = p.parse_args()
state = Path(a.state_dir).resolve()
prior = json.loads((state / 'report.json').read_text())
private = json.loads((state / 'operator-private.json').read_text())
port = private['port']
with socket.socket() as check:
    if check.connect_ex(('127.0.0.1', port)) == 0:
        raise SystemExit('refusing an already listening endpoint')
image, volume = prior['image'], prior['volume']
command = [a.kernel, '--session-db', str(state / 'sessions.sqlite'), '--receipt-db', str(state / 'receipts.sqlite'), '--authority-db', str(state / 'authority.sqlite'), 'mcp', 'serve-http', '--policy', str(Path(a.policy).resolve()), '--server-id', 'fs', '--shared-hosted-owner', '--listen', f'127.0.0.1:{port}', '--', 'docker', 'run', '--rm', '-i', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', f'type=volume,src={volume},dst=/workspace', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', image]
result = {'schema': 'chio.session-startup-readiness.v1', 'kernelSha256': hashlib.sha256(Path(a.kernel).read_bytes()).hexdigest(), 'priorEffects': prior['observer']['exactEffectsMatch'], 'sessions': []}
env = dict(os.environ, CHIO_AUTH_TOKEN=private['agentToken'], CHIO_ADMIN_TOKEN=private['adminToken'])
with open(state / 'restart-readiness.log', 'wb') as log:
    child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
started = time.perf_counter()
try:
    while True:
        if child.poll() is not None:
            raise RuntimeError('kernel exited during restart')
        try:
            request = urllib.request.Request(f'http://127.0.0.1:{port}/admin/health', headers={'Authorization': 'Bearer ' + private['adminToken']})
            with urllib.request.urlopen(request, timeout=30) as response:
                health = json.load(response)
                if not health.get('ok'):
                    raise RuntimeError('health response was not ready')
            break
        except urllib.error.URLError as error:
            if time.perf_counter() - started > 30:
                raise
            time.sleep(.1)
    result['authenticatedReadinessSeconds'] = time.perf_counter() - started
    def rpc(method, session=None, params=None, notification=False):
        payload = {'jsonrpc': '2.0', 'method': method}
        if not notification:
            payload['id'] = uuid.uuid4().hex
        if params is not None:
            payload['params'] = params
        headers = {'Authorization': 'Bearer ' + private['agentToken'], 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'}
        if session:
            headers['MCP-Session-Id'] = session
        begin = time.perf_counter()
        with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}/mcp', json.dumps(payload).encode(), headers), timeout=10) as response:
            raw = response.read().decode()
            data = [line[5:].strip() for line in raw.splitlines() if line.startswith('data:')]
            decoded = json.loads('\n'.join(data) if data else raw) if raw and not notification else None
            if decoded and 'error' in decoded:
                raise RuntimeError(json.dumps(decoded['error']))
            return response.headers.get('MCP-Session-Id'), time.perf_counter() - begin
    for index in range(3):
        session, init_time = rpc('initialize', params={'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'chio-startup-readiness-probe', 'version': '1'}})
        rpc('notifications/initialized', session=session, notification=True)
        _, context_time = rpc('chio/execution-context', session=session)
        result['sessions'].append({'index': index, 'initializeSeconds': init_time, 'contextSeconds': context_time})
    observed = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--mount', f'type=volume,src={volume},dst=/workspace,readonly', '--entrypoint', 'node', image, '-e', "const f=require('fs');console.log(JSON.stringify(f.readdirSync('/workspace').sort().map(name=>({name,content:f.readFileSync('/workspace/'+name,'utf8')}))))"], text=True)
    result['effectsUnchanged'] = json.loads(observed) == prior['observer']['effects']
    result['passed'] = result['effectsUnchanged'] and len(result['sessions']) == 3 and all(event['initializeSeconds'] + event['contextSeconds'] < 10 for event in result['sessions'])
finally:
    child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)
    (state / 'restart-readiness.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
