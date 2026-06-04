from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from http import HTTPStatus
from http.server import ThreadingHTTPServer

from app import (
    MAX_REQUEST_BODY_BYTES,
    Handler,
    JsonRequestError,
    decode_json_body,
    echo_response,
    parse_content_length,
)


class RequestBoundaryTests(unittest.TestCase):
    def test_parse_content_length_rejects_negative_values(self) -> None:
        with self.assertRaises(JsonRequestError) as raised:
            parse_content_length("-1")

        self.assertEqual(raised.exception.status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(raised.exception.payload["error"], "invalid_request")

    def test_parse_content_length_rejects_oversized_values(self) -> None:
        with self.assertRaises(JsonRequestError) as raised:
            parse_content_length(str(MAX_REQUEST_BODY_BYTES + 1))

        self.assertEqual(raised.exception.status, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        self.assertEqual(raised.exception.payload["error"], "request_too_large")

    def test_decode_json_body_requires_json_object(self) -> None:
        with self.assertRaises(JsonRequestError) as raised:
            decode_json_body(b'["not", "an", "object"]')

        self.assertEqual(raised.exception.status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(raised.exception.payload["message"], "request body must be a JSON object")

    def test_echo_response_rejects_boolean_count(self) -> None:
        with self.assertRaises(JsonRequestError) as raised:
            echo_response({"message": "hello", "count": True})

        self.assertEqual(raised.exception.status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(raised.exception.payload["message"], "count must be an integer")


class UpstreamHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    @contextmanager
    def http_error(self, status: HTTPStatus):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            yield raised
        self.assertEqual(raised.exception.code, status)

    def read_json(self, path: str) -> dict[str, object]:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def post_json(self, path: str, payload: object) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_hello_response_stays_plain_and_chio_free(self) -> None:
        body = self.read_json("/hello")

        self.assertEqual(body["message"], "hello from openapi-sidecar upstream")
        self.assertEqual(body["runtime"], "python-http-server")
        self.assertIs(body["chio_sdk"], False)

    def test_echo_validates_and_returns_plain_upstream_response(self) -> None:
        body = self.post_json("/echo", {"message": "hello", "count": 2})

        self.assertEqual(body["message"], "hello")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["handled_by"], "plain-upstream-app")
        self.assertIs(body["chio_sdk"], False)

    def test_echo_rejects_invalid_json(self) -> None:
        request = urllib.request.Request(
            f"{self.base_url}/echo",
            data=b"{",
            headers={"content-type": "application/json"},
            method="POST",
        )

        with self.http_error(HTTPStatus.BAD_REQUEST) as raised:
            urllib.request.urlopen(request, timeout=5)

        body = json.loads(raised.exception.read().decode("utf-8"))
        self.assertEqual(body["error"], "invalid_json")
