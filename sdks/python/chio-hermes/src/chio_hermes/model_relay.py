"""Operator-owned, text/function-only transport to one OpenAI model."""

from __future__ import annotations

import json
import secrets
import ssl
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class CodexSubscription:
    """Read-only native login material. Native Codex owns login and refresh."""

    access_token: str = field(repr=False)
    account_id: str = field(repr=False)

    @classmethod
    def from_cache(cls, value: Any) -> CodexSubscription:
        tokens = value.get("tokens") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or value.get("auth_mode") not in [None, "chatgpt"]
                or value.get("OPENAI_API_KEY") or not isinstance(tokens, dict)
                or any(not isinstance(tokens.get(key), str) or not tokens[key].strip()
                       or any(char in tokens[key] for char in "\r\n")
                       for key in ["access_token", "account_id"])):
            raise ValueError("native ChatGPT login cache required; use Codex login to refresh")
        return cls(tokens["access_token"], tokens["account_id"])


def _inline_text(value: Any) -> bool:
    return isinstance(value, str) or isinstance(value, list) and all(
        isinstance(part, dict) and not set(part) - {"type", "text", "annotations"}
        and part.get("type") in ["input_text", "output_text", "text"]
        and isinstance(part.get("text"), str) and part.get("annotations", []) == []
        for part in value
    )


def validate_responses_request(body: Any, model: str, tool_names: set[str]) -> list[dict[str, Any]]:
    """Validate native inline Responses history and return tool observations.

    Provider object references, hosted tools, encrypted history and account
    mutations cannot cross this relay. IDs attached to complete inline items
    are discarded; they never become remote object authority.
    """
    allowed = {"model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
               "stream", "store", "reasoning", "include", "prompt_cache_key", "prompt_cache_retention",
               "max_output_tokens", "temperature", "top_p", "text"}
    if (not isinstance(body, dict) or set(body) - allowed or body.get("model") != model
            or body.get("store") is not False or body.get("stream") is not True
            or not isinstance(body.get("instructions", ""), str)):
        raise ValueError("request exceeds selected native Responses mode")
    inputs = body.get("input")
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 512:
        raise ValueError("complete inline Responses history required")
    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise ValueError("tools must be a list")
    for tool in tools:
        if (not isinstance(tool, dict) or set(tool) - {"type", "name", "description", "parameters", "strict"}
                or tool.get("type") != "function" or not isinstance(tool.get("name"), str) or tool.get("name") not in tool_names
                or not isinstance(tool.get("parameters"), dict)):
            raise ValueError("hosted or alternate functions refused")
    choice = body.get("tool_choice", "auto")
    if isinstance(choice, dict):
        if set(choice) != {"type", "name"} or choice["type"] != "function" or not isinstance(choice["name"], str) or choice["name"] not in tool_names:
            raise ValueError("alternate tool choice refused")
    elif choice not in ["auto", "none", "required"]:
        raise ValueError("alternate tool choice refused")
    if "parallel_tool_calls" in body and type(body["parallel_tool_calls"]) is not bool:
        raise ValueError("parallel tool mode refused")
    reasoning = body.get("reasoning", {})
    if (not isinstance(reasoning, dict) or set(reasoning) - {"effort", "summary"}
            or reasoning.get("effort", "medium") not in ["none", "minimal", "low", "medium", "high", "xhigh"]
            or reasoning.get("summary", "auto") not in ["auto", "concise", "detailed"]):
        raise ValueError("reasoning options refused")
    if body.get("include", []) not in [[], ["reasoning.encrypted_content"]]:
        raise ValueError("provider includes refused")
    if "max_output_tokens" in body and (type(body["max_output_tokens"]) is not int or not 0 < body["max_output_tokens"] <= 4096):
        raise ValueError("output budget refused")
    for key, maximum in [("temperature", 2), ("top_p", 1)]:
        if key in body and (type(body[key]) not in [int, float] or not 0 <= body[key] <= maximum):
            raise ValueError("sampling parameters refused")
    text_options = body.get("text", {})
    if (not isinstance(text_options, dict) or set(text_options) - {"verbosity", "format"}
            or text_options.get("verbosity", "medium") not in ["low", "medium", "high"]
            or text_options.get("format", {"type": "text"}) != {"type": "text"}):
        raise ValueError("text format refused")
    # Cache hints carry no application semantics and are not forwarded.
    body.pop("prompt_cache_key", None)
    body.pop("prompt_cache_retention", None)
    body["include"] = []
    # Native ChatGPT rejects this Chat Completions-derived custom-provider
    # limit. Bound requests locally; do not claim an upstream output-token cap.
    body.pop("max_output_tokens", None)
    observations = []
    calls = set()
    inline_items = []
    for item in inputs:
        if not isinstance(item, dict):
            raise ValueError("complete inline Responses item required")
        kind = item.get("type", "message")
        if kind == "reasoning":
            if (set(item) - {"type", "id", "summary", "encrypted_content", "status"}
                    or not isinstance(item.get("encrypted_content"), str)
                    or not isinstance(item.get("summary"), list)
                    or not all(isinstance(part, dict) and set(part) == {"type", "text"}
                               and part["type"] == "summary_text" and isinstance(part["text"], str)
                               for part in item["summary"])):
                raise ValueError("unsupported opaque Responses history")
            # Some ChatGPT models return encrypted reasoning even with include=[].
            # It is unnecessary authority: discard it, keeping full inline text
            # and function history. Never ask the provider to resolve it.
            continue
        if (kind == "message" and not set(item) - {"type", "id", "role", "content", "status", "phase"}
                and item.get("role") in ["system", "developer", "user", "assistant"]
                and _inline_text(item.get("content"))
                and item.get("phase") in [None, "commentary", "final_answer"]):
            pass
        elif (kind == "function_call" and not set(item) - {"type", "id", "call_id", "name", "arguments", "status"}
              and isinstance(item.get("name"), str) and item["name"] in tool_names
              and isinstance(item.get("arguments"), str) and isinstance(item.get("call_id"), str)):
            calls.add(item["call_id"])
        elif (kind == "function_call_output" and not set(item) - {"type", "id", "call_id", "output", "status"}
              and isinstance(item.get("call_id"), str) and item["call_id"] in calls
              and _inline_text(item.get("output"))):
            content = item["output"]
            if isinstance(content, list):
                content = [{"type": "text", "text": part["text"]} for part in content]
            observations.append({"role": "tool", "tool_call_id": item["call_id"], "content": content})
        else:
            raise ValueError("unsupported or referenced Responses history")
        item.pop("id", None)
        item.pop("status", None)
        inline_items.append(item)
    if not inline_items:
        raise ValueError("complete inline Responses history required")
    body["input"] = inline_items
    return observations


class ModelRelay:
    """The model key stays in this unsandboxed operator process, never the host."""

    def __init__(self, api_key: str | CodexSubscription, model: str, tool_names: set[str], max_requests: int = 100, on_tool_results=None) -> None:
        self.token = secrets.token_hex(32)
        self.events: list[dict[str, Any]] = []
        self._admission = threading.Lock()
        self._remaining = max_requests
        owner = self
        subscription = isinstance(api_key, CodexSubscription)
        self.api_mode = "codex_responses" if subscription else "chat_completions"
        route = "/v1/responses" if subscription else "/v1/chat/completions"
        endpoint = "https://chatgpt.com/backend-api/codex/responses" if subscription else "https://api.openai.com/v1/chat/completions"
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
                    if (self.path != route or self.headers.get("Authorization") != "Bearer " + owner.token
                            or self.headers.get("Origin") is not None
                            or self.headers.get("Host") != f"127.0.0.1:{owner.server.server_port}"
                            or not 0 < length <= 8 * 1024 * 1024):
                        raise ValueError("route or authentication refused")
                    raw = self.rfile.read(length)
                    body = json.loads(raw)
                    if subscription:
                        observations = validate_responses_request(body, model, tool_names)
                    else:
                        validate_request(body, model, tool_names)
                        observations = body["messages"]
                    if on_tool_results:
                        on_tool_results(observations)
                    with owner._admission:
                        if owner._remaining <= 0:
                            raise ValueError("model request budget exhausted")
                        owner._remaining -= 1
                    body["store"] = False
                    body["parallel_tool_calls"] = False
                    if not subscription and not {"max_tokens", "max_completion_tokens"}.intersection(body):
                        body["max_tokens"] = 4096
                    # Never forward client headers, URLs, provider references or
                    # hosted tools. This is the one qualified upstream route.
                    headers = {"Content-Type": "application/json"}
                    if subscription:
                        headers.update({"Authorization": "Bearer " + api_key.access_token,
                                        "ChatGPT-Account-Id": api_key.account_id})
                    else:
                        headers["Authorization"] = "Bearer " + api_key
                    request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), headers=headers)
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
