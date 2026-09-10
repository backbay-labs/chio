"""Disposable HTTP tests for the two scoped operator commands, without a kernel."""

import contextlib
import http.server
import importlib.util
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("operator_http", HERE / "operator_http.py")
operator_http = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator_http)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        owner = self.server.fixture
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        owner.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "body": body,
                "authorization": self.headers.get("Authorization"),
            }
        )
        route = urllib.parse.urlsplit(self.path).path
        if self.command == "POST" and route == "/admin/revocations":
            owner.revoked = True
        if owner.mode == "drop":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if owner.mode == "timeout":
            time.sleep(0.2)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        capability = query.get("capability_id", ["cap-test"])[0]
        if self.command == "POST" and route == "/admin/revocations":
            capability = json.loads(body)["capability_id"]
            result = {"capabilityId": capability, "revoked": True, "newlyRevoked": True}
        elif route == "/admin/revocations":
            result = {
                "configured": True,
                "capabilityId": capability,
                "revoked": owner.revoked,
                "count": int(owner.revoked),
                "revocations": (
                    [{"capabilityId": capability, "revokedAt": 1}] if owner.revoked else []
                ),
            }
        elif route == "/admin/budgets":
            result = {
                "configured": True,
                "capabilityId": capability,
                "count": 1,
                "usages": [
                    {
                        "capabilityId": capability,
                        "grantIndex": 0,
                        "invocationCount": 3,
                        "updatedAt": 1789000000,
                        "totalExposureCharged": 7,
                        "totalRealizedSpend": 4,
                    }
                ],
            }
        else:
            result = {
                "status": "pending",
                "record": {"id": "approval-test", "intent": {"requestId": "request-test"}},
                "toolCallParams": {"_meta": {"approval": "decision"}},
            }
        payload = owner.payload if owner.payload is not None else json.dumps(result).encode()
        self.send_response(owner.status)
        self.send_header("Content-Type", owner.content_type)
        self.send_header("Content-Length", str(len(payload)))
        if owner.location:
            self.send_header("Location", owner.location)
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
            self.wfile.write(payload)


class Fixture:
    def __init__(self, tls=None):
        self.requests = []
        self.revoked = False
        self.mode = "normal"
        self.status = 200
        self.payload = None
        self.location = None
        self.content_type = "application/json"
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.fixture = self
        if tls:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.origin = (
            f"{'https' if tls else 'http'}://{'localhost' if tls else '127.0.0.1'}:{self.port}"
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class OperatorCommandsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.server = Fixture()
        self.sink = Fixture()
        self.addCleanup(self.server.close)
        self.addCleanup(self.sink.close)
        self.token = secrets.token_hex(32)
        self.operator = self.root / "operator.json"
        self.write_operator(
            {
                "adminToken": self.token,
                "agentToken": secrets.token_hex(32),
                "port": self.server.port,
            }
        )
        self.proposal = self.root / "proposal.json"
        self.proposal_value = {
            "session_id": "session",
            "capability_id": "cap-test",
            "request_id": "request-test",
            "tool_name": "write_file",
            "arguments": {"path": "/workspace/item", "content": "specific"},
        }
        self.proposal.write_text(json.dumps(self.proposal_value))
        self.output = self.root / "decision.json"

    def write_operator(self, value):
        self.operator.write_text(json.dumps(value))
        self.operator.chmod(0o600)

    def command(self, action="status", approval=False, extra=(), env=None):
        args = [
            sys.executable,
            str(HERE / ("operator_approval.py" if approval else "operator_capability.py")),
            action,
            "--operator-file",
            str(self.operator),
        ]
        if approval:
            args += ["--output", str(self.output)]
            args += (
                ["--proposal-file", str(self.proposal)]
                if action == "submit"
                else ["--approval-id", "approval-test"]
            )
        else:
            args += ["--capability-id", "cap-test"]
        result = subprocess.run([*args, *extra], capture_output=True, text=True, env=env, timeout=5)
        # A failing assertion must not print the random credential either.
        self.assertTrue(
            self.token not in result.stdout + result.stderr, "private token escaped public output"
        )
        return result

    def test_capability_status_revoke_and_budget_are_exactly_scoped(self):
        before = self.command()
        self.assertEqual(before.returncode, 0)
        self.assertFalse(json.loads(before.stdout)["result"]["revoked"])
        revoked = self.command("revoke")
        self.assertEqual(revoked.returncode, 0)
        self.assertTrue(self.server.revoked)
        self.assertTrue(json.loads(self.command().stdout)["result"]["revoked"])
        budget = json.loads(self.command("budget").stdout)["result"]
        self.assertEqual(budget["usages"][0]["invocationCount"], 3)
        self.assertEqual(budget["usages"][0]["totalExposureCharged"], 7)
        self.assertFalse(budget["mayBeTruncated"])
        for request in self.server.requests:
            self.assertTrue(request["authorization"] == "Bearer " + self.token)
            if request["method"] == "POST":
                self.assertEqual(json.loads(request["body"]), {"capability_id": "cap-test"})
            else:
                self.assertEqual(
                    urllib.parse.parse_qs(urllib.parse.urlsplit(request["path"]).query)[
                        "capability_id"
                    ],
                    ["cap-test"],
                )

    def test_approval_actions_preserve_exact_payload_and_private_artifact(self):
        for action in ("submit", "show", "approve", "deny"):
            with self.subTest(action=action):
                result = self.command(action, approval=True)
                self.assertEqual(result.returncode, 0)
                saved = json.loads(self.output.read_text())
                self.assertEqual(saved["toolCallParams"], {"_meta": {"approval": "decision"}})
                self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
                request = self.server.requests[-1]
                if action == "submit":
                    self.assertEqual(json.loads(request["body"]), self.proposal_value)
                elif action == "show":
                    self.assertEqual(request["method"], "GET")
                    self.assertEqual(request["path"], "/admin/approvals/approval-test")
                else:
                    self.assertEqual(
                        json.loads(request["body"]),
                        {"decision": "approved" if action == "approve" else "denied"},
                    )
                    self.assertEqual(request["path"], "/admin/approvals/approval-test/decision")
                self.output.unlink()

    def test_redirects_never_forward_credentials_or_replay_mutations(self):
        for status in (301, 302, 303, 307, 308):
            for approval, action in (
                (False, "status"),
                (False, "budget"),
                (False, "revoke"),
                (True, "submit"),
                (True, "show"),
                (True, "approve"),
                (True, "deny"),
            ):
                with self.subTest(status=status, approval=approval, action=action):
                    self.server.status = status
                    self.server.location = self.sink.origin + "/stolen"
                    before = len(self.server.requests)
                    result = self.command(action, approval=approval)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(len(self.server.requests), before + 1)
                    self.assertEqual(len(self.sink.requests), 0)
                    saved = (
                        json.loads(self.output.read_text())
                        if approval
                        else json.loads(result.stderr)
                    )
                    self.assertEqual(saved["error"], "redirect_refused")
                    self.assertEqual(saved["httpStatus"], status)
                    if self.output.exists():
                        self.output.unlink()

    def test_same_origin_redirect_also_refused(self):
        self.server.status = 302
        self.server.location = self.server.origin + "/alternate"
        self.assertEqual(self.command().returncode, 1)
        self.assertEqual(len(self.server.requests), 1)

    def test_environment_proxy_does_not_receive_bearer(self):
        env = dict(
            os.environ,
            HTTP_PROXY=self.sink.origin,
            http_proxy=self.sink.origin,
            HTTPS_PROXY=self.sink.origin,
            https_proxy=self.sink.origin,
            ALL_PROXY=self.sink.origin,
            all_proxy=self.sink.origin,
            NO_PROXY="",
            no_proxy="",
        )
        self.assertEqual(self.command(env=env).returncode, 0)
        self.assertEqual(self.command("submit", approval=True, env=env).returncode, 0)
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual(len(self.sink.requests), 0)

    def test_lost_revoke_response_keeps_unknown_without_retry(self):
        self.server.mode = "drop"
        result = self.command("revoke")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["outcome"], "unknown")
        self.assertTrue(self.server.revoked)
        self.assertEqual(len(self.server.requests), 1)
        self.server.mode = "normal"
        self.assertTrue(json.loads(self.command().stdout)["result"]["revoked"])
        self.assertEqual(len(self.server.requests), 2)

    def test_http_json_and_timeout_failures_have_no_private_diagnostics(self):
        cases = [
            (401, b"private " + self.token.encode(), "text/plain", "normal"),
            (500, self.token.encode(), "text/plain", "normal"),
            (200, b'{"private":"' + self.token.encode(), "application/json", "normal"),
            (200, b"{}", "text/plain", "normal"),
            (200, b"{}", "application/json", "timeout"),
        ]
        for status, payload, kind, mode in cases:
            for approval in (False, True):
                with self.subTest(status=status, mode=mode, approval=approval):
                    self.server.status, self.server.payload = status, payload
                    self.server.content_type, self.server.mode = kind, mode
                    result = self.command(
                        "show" if approval else "status",
                        approval=approval,
                        extra=("--timeout", "0.05"),
                    )
                    self.assertEqual(result.returncode, 1)
                    if self.output.exists():
                        self.assertTrue(self.token not in self.output.read_text())
                        self.output.unlink()

    def test_mismatched_or_unconfigured_capability_response_rejected(self):
        for response in (
            {"capabilityId": self.token},
            {"capabilityId": "other"},
            {"capabilityId": "cap-test", "configured": False},
            {
                "capabilityId": "cap-test",
                "configured": True,
                "count": 1,
                "revoked": False,
                "revocations": [{"capabilityId": "other"}],
            },
            {
                "capabilityId": "cap-test",
                "configured": True,
                "count": 0,
                "revoked": self.token,
                "revocations": [],
            },
        ):
            self.server.payload = json.dumps(response).encode()
            self.assertEqual(self.command().returncode, 1)

    def test_response_extensions_are_not_echoed(self):
        self.server.payload = json.dumps(
            {
                "capabilityId": "cap-test",
                "configured": True,
                "count": 0,
                "revocations": [],
                "revoked": False,
                "diagnostic": self.token,
            }
        ).encode()
        result = self.command()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("diagnostic", json.loads(result.stdout)["result"])

    def test_private_file_and_identifier_rejections_precede_requests(self):
        for identifier in ("", " ", "*", "cap/test", "cap?x=y", "cap\nheader", self.token):
            self.assertEqual(self.command(extra=("--capability-id", identifier)).returncode, 1)
        self.operator.chmod(0o644)
        self.assertEqual(self.command().returncode, 1)
        self.operator.chmod(0o600)
        moved = self.root / "actual.json"
        self.operator.rename(moved)
        self.operator.symlink_to(moved)
        self.assertEqual(self.command().returncode, 1)
        self.operator.unlink()
        self.assertEqual(self.command().returncode, 1)
        for value in (
            [],
            {},
            {"adminToken": "bad\r\nheader", "port": self.server.port},
            {"adminToken": self.token, "agentToken": self.token, "port": self.server.port},
            {"adminToken": self.token, "port": True},
            {"adminToken": self.token, "port": 65536},
        ):
            self.write_operator(value)
            self.assertEqual(self.command().returncode, 1)
        self.assertEqual(len(self.server.requests), 0)

    def test_ambiguous_or_untrusted_origins_precede_requests(self):
        for base in (
            "http://example.com",
            "file:///tmp/test",
            "https://",
            "https://user@host",
            "https://host/path",
            "https://host?",
            "https://host#",
            "https://host:0",
            "https://host:65536",
            "https://host:",
            " https://host",
            "https://ho\nst",
            "https://127.0.0.1%2f.evil",
            "http://127.1",
            "http://localhost.evil",
            "https://host\\@other",
            "https://[::1",
        ):
            self.assertEqual(self.command(extra=("--base-url", base)).returncode, 1)
        self.assertEqual(len(self.server.requests), 0)
        self.assertEqual(operator_http.origin("http://localhost:42", {}), "http://127.0.0.1:42")
        self.assertEqual(operator_http.origin("http://[::1]:42", {}), "http://[::1]:42")
        self.assertEqual(
            operator_http.origin("https://admin.example:443/", {}), "https://admin.example:443"
        )

    def test_existing_output_or_bad_proposal_prevents_approval_effect(self):
        self.output.write_text("retained")
        self.assertEqual(self.command("approve", approval=True).returncode, 1)
        self.assertEqual(self.output.read_text(), "retained")
        self.output.unlink()
        self.proposal.write_text('{"request":1,"request":2}')
        self.assertEqual(self.command("submit", approval=True).returncode, 1)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self.server.requests), 0)

    def test_duplicate_json_nonfinite_and_oversized_responses_rejected(self):
        for payload in (
            b'{"capabilityId":"cap-test","capabilityId":"other"}',
            b'{"value":NaN}',
            b'{"value":1e400}',
            b" " * (operator_http.MAX_JSON_BYTES + 1),
        ):
            self.server.payload = payload
            self.assertEqual(self.command().returncode, 1)

    def test_untrusted_https_sends_no_authorization_and_explicit_ca_succeeds(self):
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        generated = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(generated.returncode, 0, "local certificate fixture creation failed")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        fixture = Fixture(context)
        self.addCleanup(fixture.close)
        self.assertEqual(self.command(extra=("--base-url", fixture.origin)).returncode, 1)
        self.assertEqual(len(fixture.requests), 0)
        env = dict(os.environ, SSL_CERT_FILE=str(cert))
        self.assertEqual(self.command(extra=("--base-url", fixture.origin), env=env).returncode, 0)
        self.assertEqual(len(fixture.requests), 1)


if __name__ == "__main__":
    unittest.main()
