"""Operator-owned, text/function-only transport to one OpenAI model."""

from __future__ import annotations

import json
import secrets
import ssl
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import certifi


def validate_request(body: Any, model: str, tool_names: set[str]) -> None:
    allowed = {"model", "messages", "tools", "tool_choice", "parallel_tool_calls", "stream",
               "stream_options", "max_tokens", "max_completion_tokens", "temperature", "top_p",
               "frequency_penalty", "presence_penalty", "seed", "stop", "store"}
    if not isinstance(body, dict) or set(body) - allowed or body.get("model") != model:
        raise ValueError("request exceeds selected model mode")
    if body.get("store", False) is not False or type(body.get("stream", False)) is not bool:
        raise ValueError("storage and stream mode refused")
    for key in ["max_tokens", "max_completion_tokens"]:
        if key in body and (type(body[key]) is not int or not 0 < body[key] <= 4096):
            raise ValueError("output budget refused")
    for key, low, high in [("temperature", 0, 2), ("top_p", 0, 1),
                           ("frequency_penalty", -2, 2), ("presence_penalty", -2, 2)]:
        if key in body and (type(body[key]) not in (int, float) or not low <= body[key] <= high):
            raise ValueError("sampling parameters refused")
    if "parallel_tool_calls" in body and type(body["parallel_tool_calls"]) is not bool:
        raise ValueError("parallel tool mode refused")
    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise ValueError("tools must be a list")
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {"type", "function"} or tool["type"] != "function":
            raise ValueError("hosted tools refused")
        function = tool["function"]
        if (not isinstance(function, dict) or set(function) - {"name", "description", "parameters", "strict"}
                or not isinstance(function.get("name"), str) or function["name"] not in tool_names
                or not isinstance(function.get("parameters"), dict)):
            raise ValueError("alternate function refused")
    choice = body.get("tool_choice", "auto")
    if isinstance(choice, dict):
        if (set(choice) != {"type", "function"} or choice["type"] != "function"
                or not isinstance(choice["function"], dict) or set(choice["function"]) != {"name"}
                or not isinstance(choice["function"]["name"], str) or choice["function"]["name"] not in tool_names):
            raise ValueError("alternate tool choice refused")
    elif choice not in ["auto", "none", "required"]:
        raise ValueError("tool choice refused")
    options = body.get("stream_options", {})
    if (not isinstance(options, dict) or set(options) - {"include_usage"}
            or "include_usage" in options and type(options["include_usage"]) is not bool):
        raise ValueError("stream options refused")
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 512:
        raise ValueError("message history refused")
    for message in messages:
        if (not isinstance(message, dict)
                or set(message) - {"role", "content", "name", "tool_calls", "tool_call_id"}
                or not isinstance(message.get("role"), str)
                or message["role"] not in {"system", "developer", "user", "assistant", "tool"}):
            raise ValueError("nonlocal message reference refused")
        content = message.get("content")
        if isinstance(content, list):
            for part in content:
                if (not isinstance(part, dict) or set(part) != {"type", "text"}
                        or part["type"] != "text" or not isinstance(part["text"], str)):
                    raise ValueError("only inline text content is supported")
        elif content is not None and not isinstance(content, str):
            raise ValueError("nontext content refused")
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list):
            raise ValueError("function history refused")
        for call in calls:
            if (not isinstance(call, dict) or set(call) != {"id", "type", "function"}
                    or call["type"] != "function" or not isinstance(call["id"], str)):
                raise ValueError("nonlocal function reference refused")
            function = call["function"]
            if (not isinstance(function, dict) or set(function) != {"name", "arguments"}
                    or not isinstance(function["name"], str) or function["name"] not in tool_names
                    or not isinstance(function["arguments"], str)):
                raise ValueError("alternate function history refused")


class ModelRelay:
    """The model key stays in this unsandboxed operator process, never the host."""

    def __init__(self, api_key: str, model: str, tool_names: set[str], max_requests: int = 100, on_tool_results=None) -> None:
        self.token = secrets.token_hex(32)
        self.events: list[dict[str, Any]] = []
        self._admission = threading.Lock()
        self._remaining = max_requests
        owner = self
        tls_context = ssl.create_default_context(cafile=certifi.where())

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                event: dict[str, Any] = {"method": "POST", "path": self.path, "forwarded": False}
                owner.events.append(event)
                headers_sent = False
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if (self.path != "/v1/chat/completions" or self.headers.get("Authorization") != "Bearer " + owner.token
                            or not 0 < length <= 8 * 1024 * 1024):
                        raise ValueError("route or authentication refused")
                    raw = self.rfile.read(length)
                    body = json.loads(raw)
                    validate_request(body, model, tool_names)
                    if on_tool_results:
                        on_tool_results(body["messages"])
                    with owner._admission:
                        if owner._remaining <= 0:
                            raise ValueError("model request budget exhausted")
                        owner._remaining -= 1
                    body["store"] = False
                    body["parallel_tool_calls"] = False
                    if not {"max_tokens", "max_completion_tokens"}.intersection(body):
                        body["max_tokens"] = 4096
                    # Never forward client headers, URLs, provider references or
                    # hosted tools. This is the one qualified upstream route.
                    request = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=json.dumps(body).encode(),
                        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})
                    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=tls_context))
                    event["forwarded"] = True
                    try:
                        upstream = opener.open(request, timeout=60)
                    except urllib.error.HTTPError as exc:
                        upstream = exc
                    with upstream:
                        event["upstream_status"] = upstream.status
                        self.send_response(upstream.status)
                        self.send_header("Content-Type", upstream.headers.get("Content-Type", "application/json"))
                        self.end_headers()
                        headers_sent = True
                        while chunk := upstream.read1(65536):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                except (ValueError, OSError, urllib.error.URLError) as exc:
                    event["error_type"] = type(exc).__name__
                    if isinstance(exc, ValueError):
                        event["reason"] = str(exc)
                    if isinstance(exc, urllib.error.URLError):
                        event["reason"] = str(exc.reason)
                    if not headers_sent:
                        self.send_response(502 if event["forwarded"] else 403)
                        self.end_headers()
                        self.wfile.write(b'{"error":{"message":"Model relay refused this request"}}')

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/v1"

    def __enter__(self) -> ModelRelay:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None
