from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent / "review_server.py"


class ProviderServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifacts = tempfile.TemporaryDirectory()
        self.addCleanup(self.artifacts.cleanup)
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PROVIDER_ARTIFACTS": self.artifacts.name},
        )

    def tearDown(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self.proc.stderr is not None:
            self.proc.stderr.close()

    def send(self, payload: dict) -> dict:
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        self.assertTrue(line, "expected JSON-RPC response")
        return json.loads(line)

    def test_lists_tools_and_quotes_release_review(self) -> None:
        initialize = self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(initialize["result"]["serverInfo"]["name"], "vanguard-security-review")

        assert self.proc.stdin is not None
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        self.proc.stdin.flush()

        tools = self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = {tool["name"] for tool in tools["result"]["tools"]}
        self.assertEqual(tool_names, {"request_quote", "execute_review", "open_dispute"})

        quote = self.send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "request_quote",
                    "arguments": {
                        "request_id": "quote_req_test_001",
                        "buyer_id": "lattice-platform-security",
                        "service_family": "security-review",
                        "target": "payments-api",
                        "requested_scope": "release-review",
                    },
                },
            }
        )
        structured = quote["result"]["structuredContent"]
        self.assertEqual(structured["price_minor"], 125000)
        self.assertTrue(structured["approval_required"])

    def test_executes_review_and_opens_dispute(self) -> None:
        _initialize = self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize"})

        assert self.proc.stdin is not None
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        self.proc.stdin.flush()

        fulfillment = self.send(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "execute_review",
                    "arguments": {
                        "job_id": "job_test_001",
                        "quote_id": "quote_test_001",
                        "service_family": "security-review",
                        "requested_scope": "hotfix-review",
                        "target": "payments-api",
                    },
                },
            }
        )
        self.assertEqual(
            fulfillment["result"]["structuredContent"]["status"],
            "completed_with_findings",
        )

        dispute = self.send(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "open_dispute",
                    "arguments": {
                        "job_id": "job_test_001",
                        "reason_code": "quality_issue",
                        "summary": "Findings lacked repro detail",
                    },
                },
            }
        )
        self.assertEqual(dispute["result"]["structuredContent"]["status"], "opened")


if __name__ == "__main__":
    unittest.main()
