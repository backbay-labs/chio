"""The provider relay accepts text/function traffic without exposing hosted tools."""

import copy
import json
import urllib.error
import urllib.request

import pytest

from chio_hermes.model_relay import ModelRelay, validate_request

MODEL = "gpt-4.1"
TOOLS = {"mcp__chio__read_text_file"}
REQUEST = {
    "model": MODEL, "messages": [{"role": "user", "content": "Read the scoped file"}],
    "tools": [{"type": "function", "function": {"name": "mcp__chio__read_text_file",
               "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}],
    "tool_choice": "auto", "stream": True, "max_tokens": 4096,
}


def test_text_and_explicit_function_history_are_supported() -> None:
    body = copy.deepcopy(REQUEST)
    body["messages"] += [{"role": "assistant", "content": None, "tool_calls": [
        {"id": "call-1", "type": "function", "function": {
            "name": "mcp__chio__read_text_file", "arguments": '{"path":"/workspace/a"}',
        }},
    ]}, {"role": "tool", "tool_call_id": "call-1", "content": "verified output"}]
    validate_request(body, MODEL, TOOLS)


@pytest.mark.parametrize("change", [
    {"model": "another-model"}, {"previous_response_id": "provider-object"},
    {"tools": [{"type": "web_search"}]},
    {"tool_choice": {"type": "function", "function": {"name": "terminal"}}},
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com"}}]}]},
    {"messages": [{"role": "assistant", "id": "provider-reference", "content": "text"}]},
    {"messages": [{"role": {}, "content": "malformed role"}]},
    {"store": True}, {"max_tokens": 4097},
])
def test_provider_references_hosted_tools_and_scope_changes_are_refused(change: dict) -> None:
    with pytest.raises(ValueError):
        validate_request({**copy.deepcopy(REQUEST), **change}, MODEL, TOOLS)


def test_invalid_local_request_never_reaches_provider() -> None:
    with ModelRelay("test-provider-key", MODEL, TOOLS) as relay:
        request = urllib.request.Request(relay.base_url + "/chat/completions",
            data=json.dumps({**REQUEST, "tools": [{"type": "web_search"}]}).encode(),
            headers={"Authorization": "Bearer " + relay.token})
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, timeout=2)
        assert rejected.value.code == 403
        assert relay.events == [{"method": "POST", "path": "/v1/chat/completions",
                                 "forwarded": False, "error_type": "ValueError", "reason": "hosted tools refused"}]
