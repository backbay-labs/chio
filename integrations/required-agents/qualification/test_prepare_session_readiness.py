"""Readiness/preparation boundary tests; fixture processes are not a Chio host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER = Path(__file__).parents[1] / 'prepare-session.py'
SPEC = importlib.util.spec_from_file_location('prepare_session', HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / 'owner'
        self.state.mkdir(mode=0o700)
        self.kernel = self.root / 'kernel'
        self.kernel.write_bytes(b'fixture kernel bytes; never executed')
        self.kernel.chmod(0o555)
        self.bridge = self.root / 'bridge'
        (self.bridge / 'dist').mkdir(parents=True)
        (self.bridge / 'dist/prepare-gateway.js').write_text('// fixture, never executed\n')
        self.signer = self.state / 'sessions.sqlite.admission.kernel.pub'
        self.operator = {
            'stateDir': str(self.state),
            'command': [str(self.kernel), '--session-db', str(self.state / 'sessions.sqlite'),
                        '--listen', '127.0.0.1:59212'],
            'kernelSha256': hashlib.sha256(self.kernel.read_bytes()).hexdigest(),
            'port': 59212, 'agentToken': 'fixture-agent', 'adminToken': 'fixture-admin',
        }
        self.save_operator()
        (self.state / 'kernel.pid').write_text(str(os.getpid()))

    def save_operator(self):
        path = self.state / 'operator.json'
        path.write_text(json.dumps(self.operator))
        path.chmod(0o600)

    def assert_no_preparation(self):
        self.assertEqual(list(self.state.glob('new-session-*')), [])

    def test_late_signer_waits_without_allocating_or_dispatching(self):
        def publish(_):
            self.assert_no_preparation()
            self.signer.write_text('a' * 64 + '\n')
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.time, 'sleep', side_effect=publish), \
                patch.object(MODULE.subprocess, 'run') as run:
            operator, signer = MODULE.wait_for_owner(self.state, 2)
        self.assertEqual(operator, self.operator)
        self.assertEqual(signer, 'a' * 64)
        run.assert_not_called()
        self.assert_no_preparation()

    def test_missing_signer_timeout_preserves_owner_and_makes_no_network_call(self):
        before = (self.state / 'operator.json').read_bytes()
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.subprocess, 'run') as run:
            with self.assertRaises(TimeoutError):
                MODULE.prepare(self.state, self.bridge, 0.03)
        run.assert_not_called()
        self.assertEqual((self.state / 'operator.json').read_bytes(), before)
        self.assert_no_preparation()

    def test_ready_owner_allocates_once_and_prepares_once(self):
        self.signer.write_text('a' * 64)
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            config = MODULE.prepare(self.state, self.bridge, 2)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(list(self.state.glob('new-session-*'))), 1)
        request = json.loads(config.with_name('prepare.json').read_text())
        self.assertEqual(request['trustedSigners'], ['a' * 64])
        self.assertEqual(request['bearerToken'], 'fixture-agent')
        self.assertEqual(run.call_args.args[0][0], 'node')

    def test_failed_preparation_is_not_retried_and_retains_original_request(self):
        self.signer.write_text('a' * 64)
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 1, '', 'fixture error')) as run:
            with self.assertRaises(RuntimeError):
                MODULE.prepare(self.state, self.bridge, 2)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(list(self.state.glob('new-session-*/prepare.json'))), 1)

    def test_wrong_state_database_hash_and_pid_are_refused(self):
        for variant in ('state', 'database', 'hash', 'pid'):
            with self.subTest(variant=variant):
                original = json.loads(json.dumps(self.operator))
                if variant == 'state':
                    self.operator['stateDir'] = str(self.root)
                elif variant == 'database':
                    self.operator['command'][2] = str(self.root / 'other.sqlite')
                elif variant == 'hash':
                    self.operator['kernelSha256'] = 'b' * 64
                else:
                    (self.state / 'kernel.pid').write_text('1')
                self.save_operator()
                with patch.object(MODULE, 'check_process'), self.assertRaises(ValueError):
                    MODULE.wait_for_owner(self.state, 1)
                self.operator = original
                self.save_operator()
                (self.state / 'kernel.pid').write_text(str(os.getpid()))
                self.assert_no_preparation()

    def test_missing_credentials_and_mismatched_listener_fail_before_allocation(self):
        for field, value in [('port', None), ('port', 59213), ('agentToken', None),
                             ('adminToken', ''), ('adminToken', 'fixture-agent')]:
            with self.subTest(field=field, value=value):
                previous = self.operator[field]
                self.operator[field] = value
                self.save_operator()
                with patch.object(MODULE, 'check_process'), patch.object(MODULE.subprocess, 'run') as run, \
                        self.assertRaises(ValueError):
                    MODULE.prepare(self.state, self.bridge, 1)
                run.assert_not_called()
                self.assert_no_preparation()
                self.operator[field] = previous
                self.save_operator()

    def test_symlink_hardlink_and_writable_signer_are_refused(self):
        target = self.root / 'unrelated-key'
        target.write_text('a' * 64)
        for variant in ('symlink', 'hardlink', 'writable'):
            with self.subTest(variant=variant):
                if variant == 'symlink':
                    self.signer.symlink_to(target)
                elif variant == 'hardlink':
                    os.link(target, self.signer)
                else:
                    self.signer.write_text('a' * 64)
                    self.signer.chmod(0o666)
                with patch.object(MODULE, 'check_process'), self.assertRaises((ValueError, OSError)):
                    MODULE.wait_for_owner(self.state, 1)
                self.signer.unlink()
                self.assert_no_preparation()

    def test_fifo_readiness_file_is_rejected_without_blocking(self):
        os.mkfifo(self.signer)
        for call in ['m.owned_text(pathlib.Path(sys.argv[2]))',
                     'm.kernel_digest(pathlib.Path(sys.argv[2]),time.monotonic()+1)']:
            with self.subTest(call=call):
                script = ('import importlib.util,pathlib,sys,time; s=importlib.util.spec_from_file_location("p",sys.argv[1]); '
                          'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); ' + call)
                result = subprocess.run([sys.executable, '-c', script, str(HELPER), str(self.signer)],
                                        capture_output=True, text=True, timeout=2)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('regular file', result.stderr)
        self.assert_no_preparation()

    def test_dead_owner_and_changed_record_during_wait_are_refused(self):
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.os, 'kill', side_effect=ProcessLookupError), \
                self.assertRaises(ProcessLookupError):
            MODULE.wait_for_owner(self.state, 1)
        def change(_):
            self.operator['port'] = 59213
            self.save_operator()
            self.signer.write_text('a' * 64)
        with patch.object(MODULE, 'check_process'), patch.object(MODULE.time, 'sleep', side_effect=change), \
                self.assertRaisesRegex(ValueError, 'identity changed'):
            MODULE.wait_for_owner(self.state, 1)
        self.assert_no_preparation()

    def test_deadline_and_record_change_during_final_hash_cannot_return_success(self):
        self.signer.write_text('a' * 64)
        original = MODULE.kernel_digest
        calls = 0
        def change(path, deadline):
            nonlocal calls
            calls += 1
            result = original(path, deadline)
            if calls == 2:
                self.operator['port'] = 59213
                self.save_operator()
            return result
        with patch.object(MODULE, 'check_process'), patch.object(MODULE, 'kernel_digest', side_effect=change), \
                self.assertRaisesRegex(ValueError, 'identity changed'):
            MODULE.wait_for_owner(self.state, 1)
        self.operator['port'] = 59212
        self.save_operator()
        def delay(path, deadline):
            result = original(path, deadline)
            time.sleep(0.03)
            return result
        with patch.object(MODULE, 'check_process'), patch.object(MODULE, 'kernel_digest', side_effect=delay), \
                self.assertRaises(TimeoutError):
            MODULE.wait_for_owner(self.state, 0.01)
        self.assert_no_preparation()

    def test_actual_native_process_identity_rejects_wrong_command(self):
        # Framework Python launchers can re-exec a different binary. The owner
        # contract requires one native executable with its exact recorded argv.
        executable = Path('/bin/sleep').resolve(strict=True)
        command = [str(executable), '10']
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.05)
            MODULE.check_process(process.pid, command, executable, time.monotonic() + 2)
            with self.assertRaises(ValueError):
                MODULE.check_process(process.pid, command + ['wrong'], executable, time.monotonic() + 2)
        finally:
            process.terminate()
            process.wait(timeout=2)


if __name__ == '__main__':
    unittest.main()
