"""The framework binding executes remotely once and preserves terminal identities."""

import asyncio
from types import SimpleNamespace

import pytest

from chio_adapter_base.mcp import McpOutcomeUnknown, McpToolBinding, McpToolError


def result(number=1, error=False):
    return {
        "content": [{"type": "text", "text": "grant exhausted" if error else "saved"}],
        "isError": error,
        "_meta": {
            "chioReceipt": {"receiptId": f"receipt-{number}", "requestId": f"operation-{number}"}
        },
    }


def test_each_remote_call_retains_its_own_association_including_errors():
    calls = []

    def call(name, arguments):
        calls.append((name, arguments))
        return result(len(calls), len(calls) == 3)

    binding = McpToolBinding(SimpleNamespace(call=call), "save")
    first = binding.execute({"text": "one"})
    second = binding.execute({"text": "two"})
    with pytest.raises(McpToolError) as caught:
        binding.execute({"text": "three"})
    assert first.receipt_id == "receipt-1"
    assert second.request_id == "operation-2"
    assert caught.value.receipt_id == "receipt-3"
    assert caught.value.execution is binding.last_execution
    assert len(calls) == 3


def test_uncertain_transport_does_not_retry_or_claim_refusal():
    calls = []

    def call(*args):
        calls.append(args)
        raise TimeoutError("reply lost after possible effect")

    binding = McpToolBinding(SimpleNamespace(call=call), "save")
    with pytest.raises(McpOutcomeUnknown):
        binding.execute({"text": "one"})
    assert len(calls) == 1 and binding.last_execution is None


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"_meta": []},
        {"_meta": {"chioReceipt": "bad"}},
        {**result(), "isError": "false"},
        {**result(), "content": "bad"},
    ],
)
def test_malformed_reply_is_unknown_not_a_success(response):
    binding = McpToolBinding(SimpleNamespace(call=lambda *_: response), "save")
    with pytest.raises(McpOutcomeUnknown):
        binding.execute({})


def test_official_async_session_runs_on_its_owning_loop():
    async def run():
        loop = asyncio.get_running_loop()

        async def call_tool(name, arguments):
            assert asyncio.get_running_loop() is loop
            return result()

        binding = McpToolBinding(SimpleNamespace(call_tool=call_tool), "save")
        with pytest.raises(TypeError):
            binding.execute({})
        assert (await binding.aexecute({})).receipt_id == "receipt-1"

    asyncio.run(run())


def test_cancellation_is_preserved_without_repeat():
    async def run():
        calls = []

        async def call_tool(*args):
            calls.append(args)
            raise asyncio.CancelledError()

        binding = McpToolBinding(SimpleNamespace(call_tool=call_tool), "save")
        with pytest.raises(asyncio.CancelledError):
            await binding.aexecute({})
        assert len(calls) == 1 and binding.last_execution is None

    asyncio.run(run())
