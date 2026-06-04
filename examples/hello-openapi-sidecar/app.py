from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

MAX_REQUEST_BODY_BYTES = 16 * 1024


class JsonRequestError(Exception):
    def __init__(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        super().__init__(str(payload.get("message", payload.get("error", "request error"))))
        self.status = status
        self.payload = payload


def parse_content_length(value: str | None) -> int:
    if value is None:
        return 0
    try:
        length = int(value, 10)
    except ValueError as error:
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {
                "error": "invalid_request",
                "message": "content-length must be an integer",
            },
        ) from error
    if length < 0:
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {
                "error": "invalid_request",
                "message": "content-length must be non-negative",
            },
        )
    if length > MAX_REQUEST_BODY_BYTES:
        raise JsonRequestError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            {
                "error": "request_too_large",
                "message": f"request body must be at most {MAX_REQUEST_BODY_BYTES} bytes",
            },
        )
    return length


def decode_json_body(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_json", "message": "request body must be valid JSON"},
        ) from error
    if not isinstance(payload, dict):
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_request", "message": "request body must be a JSON object"},
        )
    return payload


def echo_response(payload: dict[str, object]) -> dict[str, object]:
    message = payload.get("message")
    if not isinstance(message, str) or not message:
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_request", "message": "message is required"},
        )

    count = payload.get("count", 1)
    if not isinstance(count, int) or isinstance(count, bool):
        raise JsonRequestError(
            HTTPStatus.BAD_REQUEST,
            {"error": "invalid_request", "message": "count must be an integer"},
        )

    return {
        "message": message,
        "count": count,
        "handled_by": "plain-upstream-app",
        "chio_sdk": False,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "hello-openapi-sidecar/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, object] | None:
        try:
            length = parse_content_length(self.headers.get("content-length"))
            return decode_json_body(self.rfile.read(length))
        except JsonRequestError as error:
            self._json(error.status, error.payload)
            return None

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/hello":
            self._json(
                HTTPStatus.OK,
                {
                    "message": "hello from openapi-sidecar upstream",
                    "runtime": "python-http-server",
                    "chio_sdk": False,
                },
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/echo":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        payload = self._read_json_body()
        if payload is None:
            return

        try:
            response = echo_response(payload)
        except JsonRequestError as error:
            self._json(error.status, error.payload)
            return

        self._json(HTTPStatus.OK, response)


def main() -> None:
    port = int(os.environ.get("HELLO_OPENAPI_SIDECAR_PORT", "8041"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
