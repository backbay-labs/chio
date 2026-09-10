"""The provider relay accepts text/function traffic without exposing hosted tools."""

import copy
import json
import urllib.error
import urllib.request

import pytest

from chio_hermes.model_relay import (
    CodexSubscription,
    ModelRelay,
    validate_request,
    validate_responses_request,
)

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


RESPONSES = {
    "model": "gpt-5.4", "instructions": "Use the scoped tools", "store": False, "stream": True,
    "input": [{"role": "user", "content": [{"type": "input_text", "text": "Read"}]}],
    "tools": [{"type": "function", "name": "mcp__chio__read_text_file", "parameters": {"type": "object"}}],
    "include": ["reasoning.encrypted_content"], "reasoning": {"effort": "medium", "summary": "auto"},
}


def test_subscription_cache_is_explicit_and_native_login_owned() -> None:
    auth = CodexSubscription.from_cache({"auth_mode": "chatgpt", "tokens": {
        "access_token": "operator-secret", "account_id": "selected-account", "refresh_token": "never-use"}})
    assert auth.access_token == "operator-secret"
    assert auth.account_id == "selected-account"
    assert not hasattr(auth, "refresh_token")


@pytest.mark.parametrize("value", [None, {}, {"OPENAI_API_KEY": "api-key"},
    {"auth_mode": "api-key", "tokens": {"access_token": "a", "account_id": "b"}},
    {"tokens": {"access_token": "a\ninjected", "account_id": "b"}},
    {"tokens": {"access_token": "a", "account_id": None}}])
def test_subscription_invalid_auth_cache_refuses(value) -> None:
    with pytest.raises(ValueError, match="native ChatGPT"):
        CodexSubscription.from_cache(value)


def test_native_responses_tool_results_reach_existing_delivery_verifier() -> None:
    body = copy.deepcopy(RESPONSES)
    body["max_output_tokens"] = 4096
    body["input"].append({"type": "reasoning", "encrypted_content": "opaque-is-not-forwarded", "summary": []})
    body["input"] += [
        {"type": "function_call", "id": "fc_providerid", "call_id": "call_a", "name": "mcp__chio__read_text_file",
         "arguments": '{"path":"/workspace/a"}', "status": "completed"},
        {"type": "function_call_output", "call_id": "call_a", "output": "exact native result"},
    ]
    observations = validate_responses_request(body, "gpt-5.4", TOOLS)
    assert observations == [{"role": "tool", "tool_call_id": "call_a", "content": "exact native result"}]
    assert "id" not in body["input"][1]
    assert "status" not in body["input"][1]
    assert body["include"] == []
    assert "max_output_tokens" not in body
    assert all(item.get("type") != "reasoning" for item in body["input"])


@pytest.mark.parametrize("change", [
    {"model": "other"}, {"previous_response_id": "remote-state"}, {"store": True}, {"stream": False},
    {"tools": [{"type": "web_search"}]}, {"tools": [{"type": "function", "name": "terminal", "parameters": {}}]},
    {"tool_choice": {"type": "web_search"}}, {"include": ["file_search_call.results"]},
    {"input": [{"type": "item_reference", "id": "private-account-item"}]},
    {"input": [{"type": "function_call_output", "call_id": "unpaired", "output": "fake"}]},
    {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://other"}]}]},
    {"input": [{"type": "reasoning", "encrypted_content": "foreign-account", "summary": []}]},
])
def test_native_responses_hosted_and_referenced_actions_refuse(change) -> None:
    with pytest.raises(ValueError):
        validate_responses_request({**copy.deepcopy(RESPONSES), **change}, "gpt-5.4", TOOLS)


def test_subscription_relays_native_route_and_delivery_callback_without_leaking_auth(monkeypatch) -> None:
    import io
    observed = {}
    class Reply(io.BytesIO):
        status = 200
        headers = {"Content-Type": "text/event-stream"}
    class Opener:
        def open(self, request, timeout):
            observed["url"] = request.full_url
            observed["headers"] = dict(request.header_items())
            observed["body"] = json.loads(request.data)
            return Reply(b'data: {"type":"response.completed"}\n\n')
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    observations = []
    # Local request uses a separate opener because the trusted upstream is mocked.
    local = urllib.request.OpenerDirector()
    local.add_handler(urllib.request.HTTPHandler())
    local.add_handler(urllib.request.HTTPDefaultErrorHandler())
    local.add_handler(urllib.request.HTTPErrorProcessor())
    with ModelRelay(CodexSubscription("native-token", "account"), "gpt-5.4", TOOLS,
                    on_tool_results=observations.append) as relay:
        request = urllib.request.Request(relay.base_url + "/responses", data=json.dumps(RESPONSES).encode(),
            headers={"Authorization": "Bearer " + relay.token})
        assert local.open(request).status == 200
        assert observed["url"] == "https://chatgpt.com/backend-api/codex/responses"
        assert observed["headers"]["Authorization"] == "Bearer native-token"
        assert observed["headers"]["Chatgpt-account-id"] == "account"
        assert observed["body"]["parallel_tool_calls"] is False
        assert observations == [[]]
        assert "native-token" not in json.dumps(relay.events)


def test_native_delivery_verification_failure_stops_next_provider_request(monkeypatch) -> None:
    forwarded = []
    class Opener:
        def open(self, request, timeout):
            forwarded.append(request)
            raise AssertionError("unverified result must not reach provider")
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    local = urllib.request.OpenerDirector()
    local.add_handler(urllib.request.HTTPHandler())
    local.add_handler(urllib.request.HTTPDefaultErrorHandler())
    local.add_handler(urllib.request.HTTPErrorProcessor())
    def reject_native_result(_messages):
        raise ValueError("host delivery proof unresolved; no new model turn")
    with ModelRelay(CodexSubscription("native-token", "account"), "gpt-5.4", TOOLS,
                    on_tool_results=reject_native_result) as relay:
        request = urllib.request.Request(relay.base_url + "/responses", data=json.dumps(RESPONSES).encode(),
            headers={"Authorization": "Bearer " + relay.token})
        with pytest.raises(urllib.error.HTTPError) as rejected:
            local.open(request)
        assert rejected.value.code == 403
        assert not forwarded
        assert relay.events[-1]["forwarded"] is False
