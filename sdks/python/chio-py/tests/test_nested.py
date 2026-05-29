from __future__ import annotations

import json
import unittest

import httpx

from chio import NestedCallbackRouter, ChioSession, elicitation_accept_result, roots_list_result, sampling_text_result


class NestedTests(unittest.TestCase):
    def test_nested_router_dispatches_and_emits_transcript(self) -> None:
        transcript = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                text=json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"ok": True}}),
            )

        session = ChioSession(
            auth_token="token",
            base_url="http://testserver",
            session_id="sess-123",
            protocol_version="2025-11-25",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        router = NestedCallbackRouter(emit=transcript.append).register(
            "sampling/createMessage",
            step_suffix="sampling-response",
            builder=lambda message, _session: sampling_text_result(
                message,
                text="sampled by test",
                model="test-model",
            ),
        )

        response = router.handle(
            {"jsonrpc": "2.0", "id": 42, "method": "sampling/createMessage"},
            session,
            step_prefix="nested/sampling",
        )

        self.assertIsNotNone(response)
        self.assertEqual(response.request["result"]["content"]["text"], "sampled by test")
        self.assertEqual(transcript[0]["step"], "nested/sampling/sampling-response")

    def test_nested_response_builders_cover_elicitation_and_roots(self) -> None:
        elicitation = elicitation_accept_result(
            {"id": 5},
            content={"answer": "accepted"},
        )
        roots = roots_list_result(
            {"id": 6},
            roots=[{"uri": "file:///workspace", "name": "workspace"}],
        )

        self.assertEqual(elicitation["result"]["action"], "accept")
        self.assertEqual(elicitation["result"]["content"]["answer"], "accepted")
        self.assertEqual(roots["result"]["roots"][0]["uri"], "file:///workspace")


if __name__ == "__main__":
    unittest.main()
