"""Run a persistent notes API behind Envoy and Chio's authorization service."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent


def request(path, body=None, token=None, base='http://127.0.0.1:10000'):
    headers = {'Content-Type': 'application/json'}
    if token is not None:
        headers['X-Chio-Capability'] = json.dumps(token, separators=(',', ':'))
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw.decode(errors='replace')
        return response.status, dict(response.headers), payload


def wait(path, base, children):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for child in children:
            if child.poll() is not None:
                raise RuntimeError(f'Service process {child.pid} exited with {child.returncode}; inspect .state/*.log')
        try:
            if request(path, base=base)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.15)
    raise RuntimeError(f'{base}{path} did not become ready; inspect .state/*.log')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='exercise real allow, refusal, revocation and authority-outage cases')
    args = parser.parse_args()
    os.chdir(ROOT)
    state = ROOT / '.state'; state.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    paths = {}
    for name, env in [('chio', 'CHIO_BIN'), ('chio-envoy-ext-authz', 'CHIO_EXT_AUTHZ_BIN'), ('envoy', 'ENVOY_BIN')]:
        binary = os.environ.get(env) or shutil.which(name)
        if not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK):
            parser.error(f'{name} is required. Follow README.md to build/install it, or set {env}.')
        paths[name] = str(Path(binary).resolve())
    # Refuse occupied listeners before starting or bootstrapping trust. Never
    # silently attach this launcher to an unrelated authority on a fixed port.
    for port in (8087, 9091, 9092, 9097, 10000):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError as error:
                parser.error(f'Port {port} is already in use: {error}. Stop the previous example before starting another.')
    children = []; logs = []
    def start(name, command):
        log = (state / (name + '.log')).open('wb'); logs.append(log)
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(child)
        return child
    try:
        start('notes', [sys.executable, 'notes.py', '--data', str(state)])
        wait('/healthz', 'http://127.0.0.1:8087', children)
        authority = start('authority', [paths['chio'], '--authority-seed-file', str(state/'authority.hex'), 'api', 'protect', '--upstream', 'http://127.0.0.1:8087', '--spec', 'openapi.yaml', '--listen', '127.0.0.1:9097', '--receipt-store', str(state/'receipts.db')])
        wait('/chio/health', 'http://127.0.0.1:9097', children)
        # Bootstrap only from this operator-owned loopback control service, before
        # accepting any receipts. Existing installations retain their selected key.
        status, _, minted = request('/v1/capabilities/mint', {'subject': 'envoy-notes-writer', 'job_uid': str(uuid.uuid4()), 'ttl_seconds': 300, 'scopes': ['tool:chio_http_authority:authorize_http_request:invoke']}, base='http://127.0.0.1:9097')
        if status != 200 or 'capability' not in minted:
            raise RuntimeError(f'Capability issuance failed: {status}')
        token = minted['capability']; signer = token['issuer']
        trusted = state/'trusted-kernel-key.txt'
        if trusted.exists() and trusted.read_text().strip() != signer:
            raise RuntimeError('Authority signer changed. Inspect your retained seed and trust file before continuing.')
        trusted.write_text(signer+'\n')
        (state/'capability.json').write_text(json.dumps(token, indent=2)+'\n')
        os.chmod(state/'capability.json', 0o600)
        start('authorization', [paths['chio-envoy-ext-authz'], '--authority-url', 'http://127.0.0.1:9097', '--trusted-kernel-key-file', str(trusted)])
        wait('/readyz', 'http://127.0.0.1:9092', children)
        start('envoy', [paths['envoy'], '-c', 'envoy.yaml', '--concurrency', '2', '--disable-hot-restart'])
        wait('/notes', 'http://127.0.0.1:10000', children)
        if not args.check:
            print('Notes API: http://127.0.0.1:10000/notes\nCapability: .state/capability.json\nReceipts: .state/receipts.db\nCtrl-C stops the services; notes, authority and receipts remain.', flush=True)
            while all(child.poll() is None for child in children):
                time.sleep(.5)
            raise RuntimeError('A service stopped; inspect .state/*.log')
        results = []
        def observe(label, expected, body=None, grant=None):
            status, headers, payload = request('/notes', body, grant)
            receipt = next((v for k,v in headers.items() if k.lower() == 'x-chio-receipt-id'), None)
            if status != expected or (expected in (200,201,403) and not receipt):
                raise AssertionError(f'{label}: status={status}, receipt={receipt}, response={payload}')
            results.append({'step':label,'status':status,'receipt_id':receipt,'response':payload})
            return payload
        before = observe('read', 200)['notes']
        observe('write without grant', 403, {'text':'must not be saved'})
        created = observe('write with signed grant', 201, {'text':'Review the Envoy deployment'}, token)
        after = observe('read saved note', 200)['notes']
        assert len(after) == len(before)+1 and any(note['id']==created['id'] for note in after)
        status, _, _ = request('/v1/capabilities/release', {'capability_id':token['id']}, base='http://127.0.0.1:9097')
        assert status == 200
        observe('write after revocation', 403, {'text':'must not be saved after revocation'}, token)
        assert request('/notes')[2]['notes'] == after
        authority.terminate(); authority.wait(timeout=10)
        status, _, _ = request('/notes', {'text':'must not be saved during outage'}, token)
        assert status >= 400
        assert request('/notes', base='http://127.0.0.1:8087')[2]['notes'] == after
        results.append({'step':'authority outage','status':status,'effect':'unchanged'})
        (state/'verification.json').write_text(json.dumps(results, indent=2)+'\n')
        print(json.dumps(results, indent=2))
    finally:
        for child in reversed(children):
            if child.poll() is None: child.terminate()
        for child in reversed(children):
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
        for log in logs: log.close()


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: pass
