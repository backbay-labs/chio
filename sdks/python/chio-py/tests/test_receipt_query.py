from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlparse

import httpx

from chio import ChioQueryError, ChioTransportError, ReceiptQueryClient


FAKE_RECEIPT = {
    "id": "receipt-001",
    "timestamp": 1700000000,
    "capability_id": "cap-001",
    "tool_server": "wrapped-http-mock",
    "tool_name": "echo_text",
    "action": {"parameters": {}, "parameter_hash": "abc123"},
    "decision": {"verdict": "allow"},
    "content_hash": "deadbeef",
    "policy_hash": "cafebabe",
    "kernel_key": "aa" * 32,
    "signature": "bb" * 64,
}


class ReceiptQueryClientTests(unittest.TestCase):
    def test_query_uses_receipt_query_endpoint_and_bearer_auth(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"totalCount": 0, "receipts": []})

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok-123",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        result = client.query()

        self.assertEqual(result["totalCount"], 0)
        self.assertEqual(str(requests[0].url), "http://localhost:8080/v1/receipts/query")
        self.assertEqual(requests[0].headers["Authorization"], "Bearer tok-123")

    def test_query_encodes_filters_as_camel_case_query_parameters(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"totalCount": 0, "receipts": []})

        client = ReceiptQueryClient(
            "http://localhost:8080/",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        client.query(
            {
                "capabilityId": "cap-001",
                "toolServer": "wrapped-http-mock",
                "toolName": "echo_text",
                "limit": 10,
                "cursor": 5,
            }
        )

        parsed = urlparse(str(requests[0].url))
        params = parse_qs(parsed.query)
        self.assertEqual(params["capabilityId"], ["cap-001"])
        self.assertEqual(params["toolServer"], ["wrapped-http-mock"])
        self.assertEqual(params["toolName"], ["echo_text"])
        self.assertEqual(params["limit"], ["10"])
        self.assertEqual(params["cursor"], ["5"])

    def test_query_returns_typed_response(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"totalCount": 1, "nextCursor": 42, "receipts": [FAKE_RECEIPT]},
            )

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        result = client.query()

        self.assertEqual(result["totalCount"], 1)
        self.assertEqual(result["nextCursor"], 42)
        self.assertEqual(result["receipts"][0]["id"], "receipt-001")

    def test_query_raises_chio_query_error_for_non_success_status(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        with self.assertRaises(ChioQueryError) as exc:
            client.query()
        self.assertEqual(exc.exception.status, 404)

    def test_query_raises_chio_transport_error_for_network_failures(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("ECONNREFUSED")

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        with self.assertRaises(ChioTransportError):
            client.query()

    def test_paginate_yields_non_empty_pages_until_next_cursor_is_absent(self) -> None:
        pages = iter(
            [
                {"totalCount": 3, "nextCursor": 2, "receipts": [{**FAKE_RECEIPT, "id": "r1"}]},
                {"totalCount": 3, "nextCursor": 3, "receipts": [{**FAKE_RECEIPT, "id": "r2"}]},
                {"totalCount": 3, "receipts": [{**FAKE_RECEIPT, "id": "r3"}]},
            ]
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=next(pages))

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        collected = [[receipt["id"] for receipt in page] for page in client.paginate()]

        self.assertEqual(collected, [["r1"], ["r2"], ["r3"]])


if __name__ == "__main__":
    unittest.main()
