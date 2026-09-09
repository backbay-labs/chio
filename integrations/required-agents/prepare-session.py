#!/usr/bin/env python3
"""Prepare new operator-authorized test work; never use this to recover unknown work."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--operator-state', type=Path, required=True)
parser.add_argument('--bridge', type=Path, required=True, help='Installed @chio/bridge directory')
args = parser.parse_args()
state = args.operator_state.resolve(strict=True)
if state.stat().st_mode & 0o077 or state.stat().st_uid != os.getuid():
    parser.error('operator state must be a private owned directory')
operator = json.loads((state / 'operator.json').read_text())
private = state / ('new-session-' + uuid.uuid4().hex)
private.mkdir(mode=0o700)
request = {'endpoint': f"http://127.0.0.1:{operator['port']}",
           'bearerToken': operator['agentToken'], 'adminToken': operator['adminToken'],
           'credentialTtlSeconds': 900,
           'trustedSigners': [(state / 'sessions.sqlite.admission.kernel.pub').read_text().strip()],
           'serverId': 'fs', 'sessionId': str(uuid.uuid4()), 'journalDir': str(private / 'journal'),
           'allowedTools': ['read_text_file', 'write_file', 'edit_file', 'list_directory']}
source = private / 'prepare.json'
with source.open('x') as stream:
    os.chmod(source, 0o600)
    json.dump(request, stream)
    stream.flush()
    os.fsync(stream.fileno())
config = private / 'gateway.json'
result = subprocess.run(['node', str(args.bridge.resolve(strict=True) / 'dist/prepare-gateway.js'),
                         str(source), str(config)], capture_output=True, text=True, timeout=40)
if result.returncode:
    parser.exit(1, 'Session preparation failed; inspect the selected kernel and retained private state.\n')
print(config)
