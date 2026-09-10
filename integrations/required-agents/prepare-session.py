#!/usr/bin/env python3
"""Prepare new operator-authorized test work; never use this to recover unknown work."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid


def owned_text(path, *, private=False):
    """Read one owner-controlled regular file without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        forbidden = 0o077 if private else 0o022
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or metadata.st_mode & forbidden):
            raise ValueError('owner readiness files must be owned regular files with protected modes')
        text = stream.read(1024 * 1024 + 1)
        if len(text) > 1024 * 1024:
            raise ValueError('owner readiness file exceeds the size limit')
        return text


def remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('trusted signer was not ready before the deadline; owner retained, no session created')
    return remaining


def kernel_digest(path, deadline):
    digest = hashlib.sha256()
    remaining_time(deadline)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('selected kernel must be a regular file')
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            remaining_time(deadline)
            digest.update(chunk)
    remaining_time(deadline)
    return digest.hexdigest()


def check_process(pid, command, kernel, deadline):
    # Match the actual executable as well as the recorded command/session path.
    # A readable signer file or a live unrelated PID is not owner readiness.
    if sys.platform.startswith('linux'):
        remaining_time(deadline)
        process = Path('/proc') / str(pid)
        arguments = (process / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if ((process / 'exe').resolve(strict=True) != kernel
                or process.stat().st_uid != os.getuid()
                or arguments != [os.fsencode(arg) for arg in command]):
            raise ValueError('recorded PID is not the selected kernel and retained session owner')
        remaining_time(deadline)
        return
    executable = subprocess.run(['ps', '-ww', '-p', str(pid), '-o', 'comm='],
                                capture_output=True, text=True, timeout=min(2, remaining_time(deadline)))
    arguments = subprocess.run(['ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'args='],
                               capture_output=True, text=True, timeout=min(2, remaining_time(deadline)))
    fields = arguments.stdout.strip().split(None, 1)
    if (executable.returncode or arguments.returncode or len(fields) != 2
            or fields[0] != str(os.getuid()) or fields[1] != ' '.join(command)
            or Path(executable.stdout.strip()).resolve() != kernel):
        raise ValueError('recorded PID is not the selected kernel and retained session owner')
    remaining_time(deadline)


def wait_for_owner(state, timeout_seconds):
    if not 0 < timeout_seconds <= 300:
        raise ValueError('readiness timeout must be positive and at most 300 seconds')
    deadline = time.monotonic() + timeout_seconds
    state = state.resolve(strict=True)
    metadata = state.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.getuid():
        raise ValueError('operator state must be a private owned directory')
    original = owned_text(state / 'operator.json', private=True)
    operator = json.loads(original)
    if not isinstance(operator, dict):
        raise ValueError('operator record must be an object')
    command = operator.get('command')
    if (operator.get('stateDir') != str(state) or not isinstance(command, list)
            or not command or any(not isinstance(arg, str) or not arg for arg in command)
            or command.count('--session-db') != 1):
        raise ValueError('operator record does not bind this retained session owner')
    session_index = command.index('--session-db') + 1
    if session_index >= len(command) or command[session_index] != str(state / 'sessions.sqlite'):
        raise ValueError('operator command does not bind the retained session database')
    port = operator.get('port')
    if type(port) is not int or not 1024 <= port <= 65535 or command.count('--listen') != 1:
        raise ValueError('operator record requires the retained loopback listener')
    listen_index = command.index('--listen') + 1
    if listen_index >= len(command) or command[listen_index] != f'127.0.0.1:{port}':
        raise ValueError('operator origin differs from the selected kernel listener')
    if (any(not isinstance(operator.get(key), str) or not operator[key]
            for key in ('agentToken', 'adminToken'))
            or operator['agentToken'] == operator['adminToken']):
        raise ValueError('operator record requires distinct bootstrap and administrative credentials')
    kernel = Path(command[0]).resolve(strict=True)
    if (not isinstance(operator.get('kernelSha256'), str)
            or not re.fullmatch(r'[a-f0-9]{64}', operator['kernelSha256'])):
        raise ValueError('operator record requires the selected kernel SHA256')
    if kernel_digest(kernel, deadline) != operator['kernelSha256']:
        raise ValueError('selected kernel differs from retained owner identity')
    pid_text = owned_text(state / 'kernel.pid').strip()
    if not pid_text.isdecimal() or int(pid_text) <= 1:
        raise ValueError('retained owner requires a valid kernel PID')
    pid = int(pid_text)
    check_process(pid, command, kernel, deadline)
    while True:
        remaining_time(deadline)
        if (owned_text(state / 'operator.json', private=True) != original
                or owned_text(state / 'kernel.pid').strip() != pid_text):
            raise ValueError('retained owner identity changed while waiting for readiness')
        os.kill(pid, 0)
        try:
            signer = owned_text(state / 'sessions.sqlite.admission.kernel.pub').strip()
        except FileNotFoundError:
            signer = ''
        if re.fullmatch(r'[a-f0-9]{64}', signer):
            check_process(pid, command, kernel, deadline)
            if kernel_digest(kernel, deadline) != operator['kernelSha256']:
                raise ValueError('selected kernel changed while waiting for readiness')
            current = state.stat()
            if ((current.st_dev, current.st_ino, current.st_uid, current.st_mode)
                    != (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)
                    or owned_text(state / 'operator.json', private=True) != original
                    or owned_text(state / 'kernel.pid').strip() != pid_text
                    or owned_text(state / 'sessions.sqlite.admission.kernel.pub').strip() != signer):
                raise ValueError('retained owner identity changed during final readiness validation')
            remaining_time(deadline)
            return operator, signer
        if signer and (len(signer) > 64 or not re.fullmatch(r'[a-f0-9]+', signer)):
            raise ValueError('trusted owner signer file is malformed')
        time.sleep(min(0.1, remaining_time(deadline)))


def prepare(state, bridge, readiness_timeout_seconds=60):
    state = state.resolve(strict=True)
    gateway_script = bridge.resolve(strict=True) / 'dist/prepare-gateway.js'
    if not gateway_script.is_file():
        raise ValueError('selected bridge preparation executable is missing')
    operator, signer = wait_for_owner(state, readiness_timeout_seconds)
    # Do not allocate a session identity or directory until the intended owner
    # has published its trusted signer. Preparation itself still authenticates
    # the actual MCP session, authority and credential before returning success.
    private = state / ('new-session-' + uuid.uuid4().hex)
    private.mkdir(mode=0o700)
    request = {'endpoint': f"http://127.0.0.1:{operator['port']}",
               'bearerToken': operator['agentToken'], 'adminToken': operator['adminToken'],
               'credentialTtlSeconds': 900, 'trustedSigners': [signer],
               'serverId': 'fs', 'sessionId': str(uuid.uuid4()), 'journalDir': str(private / 'journal'),
               'allowedTools': ['read_text_file', 'write_file', 'edit_file', 'list_directory']}
    source = private / 'prepare.json'
    with source.open('x') as stream:
        os.chmod(source, 0o600)
        json.dump(request, stream)
        stream.flush()
        os.fsync(stream.fileno())
    config = private / 'gateway.json'
    result = subprocess.run(['node', str(gateway_script), str(source), str(config)],
                            capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise RuntimeError('session preparation failed; inspect the selected kernel and retained private state')
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator-state', type=Path, required=True)
    parser.add_argument('--bridge', type=Path, required=True, help='Installed @chio/bridge directory')
    parser.add_argument('--readiness-timeout-seconds', type=float, default=60,
                        help='Bounded signer-readiness wait before allocating a session (default: 60; maximum: 300)')
    args = parser.parse_args()
    try:
        config = prepare(args.operator_state, args.bridge, args.readiness_timeout_seconds)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        # Never emit the operator request or child output, which can contain
        # credentials. No failure path retries preparation or clears owner state.
        parser.exit(1, 'Session preparation failed or owner readiness expired; preserve the original private state and inspect the owner. No automatic retry was attempted.\n')
    print(config)


if __name__ == '__main__':
    main()
