"""Unit tests for :mod:`chio_streaming.core` primitives.

Covers the broker-agnostic helpers directly: header normalisation edge
cases (byte keys, mixed Mapping / list shapes), the synthesised-deny
forgery guard, the Slots backpressure semaphore, request-id minting,
scope resolution, body hashing, and the shared handler invoker.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient

from chio_streaming.core import (
    SYNTHETIC_RECEIPT_MARKER,
    Slots,
    hash_body,
    invoke_handler,
    new_request_id,
    normalise_headers,
    resolve_scope,
    stringify_header_value,
    synthesize_deny_receipt,
)
from chio_streaming.errors import ChioStreamingConfigError

# ---------------------------------------------------------------------------
# Slots
# ---------------------------------------------------------------------------


async def test_slots_third_acquire_blocks_until_release() -> None:
    slots = Slots(2)
    await slots.acquire()
    await slots.acquire()
    assert slots.in_flight == 2

    started = asyncio.Event()
    completed = asyncio.Event()

    async def third() -> None:
        started.set()
        await slots.acquire()
        completed.set()

    task = asyncio.create_task(third())
    await started.wait()
    # Third acquire should still be waiting because both slots are held.
    await asyncio.sleep(0.05)
    assert not completed.is_set()
    assert slots.in_flight == 2

    slots.release()
    await asyncio.wait_for(task, timeout=1.0)
    assert completed.is_set()
    assert slots.in_flight == 2
    slots.release()
    slots.release()
    assert slots.in_flight == 0


async def test_slots_release_without_acquire_is_noop() -> None:
    slots = Slots(2)
    # Release before any acquire must not raise nor underflow in_flight.
    slots.release()
    assert slots.in_flight == 0
    slots.release()
    assert slots.in_flight == 0


async def test_slots_release_more_than_acquired_is_tolerated() -> None:
    slots = Slots(2)
    await slots.acquire()
    assert slots.in_flight == 1
    slots.release()
    slots.release()
    slots.release()
    assert slots.in_flight == 0
    # Subsequent acquire still works.
    await slots.acquire()
    assert slots.in_flight == 1
    slots.release()


def test_slots_rejects_invalid_limit() -> None:
    with pytest.raises(ChioStreamingConfigError):
        Slots(0)


# ---------------------------------------------------------------------------
# new_request_id
# ---------------------------------------------------------------------------


def test_new_request_id_default_prefix_shape() -> None:
    rid = new_request_id()
    assert rid.startswith("chio-evt-")
    # "<prefix>-<32hex>"
    prefix, hex_part = rid.rsplit("-", 1)
    assert prefix == "chio-evt"
    assert len(hex_part) == 32
    int(hex_part, 16)  # parses as hex


def test_new_request_id_respects_custom_prefix() -> None:
    rid = new_request_id("chio-nats")
    assert rid.startswith("chio-nats-")
    _, hex_part = rid.rsplit("-", 1)
    assert len(hex_part) == 32


def test_new_request_id_produces_unique_ids_across_10k_calls() -> None:
    # Guards against accidental stateful / seeded generation. Also doubles
    # as the cross-broker uniqueness proof.
    ids = [new_request_id() for _ in range(10_000)]
    assert len(set(ids)) == 10_000


# ---------------------------------------------------------------------------
# synthesize_deny_receipt
# ---------------------------------------------------------------------------


def test_synthesize_deny_receipt_deterministic_hashes() -> None:
    params = {"a": 1, "b": [1, 2], "c": {"nested": True}}
    r1 = synthesize_deny_receipt(
        capability_id="cap",
        tool_server="srv",
        tool_name="tn",
        parameters=params,
        reason="nope",
        guard="g",
    )
    r2 = synthesize_deny_receipt(
        capability_id="cap",
        tool_server="srv",
        tool_name="tn",
        parameters=params,
        reason="nope",
        guard="g",
    )
    assert r1.content_hash == r2.content_hash
    assert r1.action.parameter_hash == r2.action.parameter_hash
    # Both hashes pin the canonical parameters, so they match each other.
    assert r1.content_hash == r1.action.parameter_hash


def test_synthesize_deny_receipt_is_structurally_marked_unsigned() -> None:
    receipt = synthesize_deny_receipt(
        capability_id="cap-x",
        tool_server="server",
        tool_name="events:consume:orders",
        parameters={"k": "v"},
        reason="forbidden",
        guard="scope",
    )
    assert receipt.is_denied
    assert receipt.signature == "0" * 128
    assert receipt.kernel_key == "0" * 64
    assert receipt.metadata is not None
    assert receipt.metadata["chio_streaming_synthetic"] is True
    assert receipt.metadata["chio_streaming_synthetic_marker"] == SYNTHETIC_RECEIPT_MARKER
    assert (receipt.decision.reason or "").startswith("[unsigned] ")


async def test_synthesize_deny_receipt_is_rejected_by_mock_verifier() -> None:
    receipt = synthesize_deny_receipt(
        capability_id="cap-x",
        tool_server="server",
        tool_name="events:consume:orders",
        parameters={"k": "v"},
        reason="forbidden",
        guard="scope",
    )
    chio = MockChioClient()

    assert await chio.verify_receipt(receipt) is False


def test_synthesize_deny_receipt_does_not_double_prefix() -> None:
    # Calling with a reason that is already annotated must not stack.
    receipt = synthesize_deny_receipt(
        capability_id="c",
        tool_server="s",
        tool_name="t",
        parameters={},
        reason="[unsigned] already marked",
        guard="g",
    )
    reason = receipt.decision.reason or ""
    assert reason == "[unsigned] already marked"
    assert reason.count("[unsigned]") == 1


# ---------------------------------------------------------------------------
# resolve_scope
# ---------------------------------------------------------------------------


def test_resolve_scope_explicit_mapping_wins() -> None:
    assert (
        resolve_scope(scope_map={"orders": "events:consume:orders-custom"}, subject="orders")
        == "events:consume:orders-custom"
    )


def test_resolve_scope_fallback_uses_default_prefix() -> None:
    assert resolve_scope(scope_map={}, subject="payments") == "events:consume:payments"


def test_resolve_scope_respects_custom_default_prefix() -> None:
    assert resolve_scope(scope_map={}, subject="orders", default_prefix="bus:in") == "bus:in:orders"


def test_resolve_scope_empty_subject_raises() -> None:
    with pytest.raises(ChioStreamingConfigError):
        resolve_scope(scope_map={}, subject="")


# ---------------------------------------------------------------------------
# hash_body
# ---------------------------------------------------------------------------


def test_hash_body_none_returns_none() -> None:
    assert hash_body(None) is None


def test_hash_body_empty_returns_none() -> None:
    assert hash_body(b"") is None


def test_hash_body_is_deterministic_across_calls() -> None:
    # Same bytes -> same hex. Also serves as the cross-broker
    # body_hash determinism proof.
    data = b"hello there"
    h1 = hash_body(data)
    h2 = hash_body(data)
    assert h1 is not None and h1 == h2
    assert len(h1) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# stringify_header_value
# ---------------------------------------------------------------------------


def test_stringify_header_value_utf8_bytes_decode() -> None:
    assert stringify_header_value(b"hello") == "hello"


def test_stringify_header_value_non_utf8_bytes_hex_fallback() -> None:
    assert stringify_header_value(b"\xff\xfe") == "fffe"


def test_stringify_header_value_passthrough_non_bytes() -> None:
    assert stringify_header_value("plain") == "plain"
    assert stringify_header_value(42) == 42
    assert stringify_header_value(None) is None


# ---------------------------------------------------------------------------
# normalise_headers
# ---------------------------------------------------------------------------


def test_normalise_headers_none_returns_empty_dict() -> None:
    assert normalise_headers(None) == {}


def test_normalise_headers_list_str_key_bytes_value() -> None:
    out = normalise_headers([("trace", b"abc"), ("span", b"x")])
    assert out == {"trace": "abc", "span": "x"}


def test_normalise_headers_list_bytes_key_bytes_value() -> None:
    out = normalise_headers([(b"trace", b"abc"), (b"span", b"x")])
    assert out == {"trace": "abc", "span": "x"}


def test_normalise_headers_mapping_str_bytes() -> None:
    assert normalise_headers({"trace": b"abc"}) == {"trace": "abc"}


def test_normalise_headers_mapping_bytes_bytes() -> None:
    # Both sides decoded.
    out = normalise_headers({b"trace": b"abc", b"subject": b"tasks"})
    assert out == {"trace": "abc", "subject": "tasks"}


def test_normalise_headers_non_utf8_value_hex_fallback() -> None:
    out = normalise_headers([("trace", b"\xff\xfe")])
    assert out == {"trace": "fffe"}


def test_normalise_headers_non_utf8_key_hex_fallback() -> None:
    bad = b"\xff\xfe"
    out = normalise_headers({bad: b"v"})
    assert out == {bad.hex(): "v"}


def test_normalise_headers_list_skips_falsy_items() -> None:
    # ``[("k", b"v"), None, ("k2", b"v2")]`` shape is tolerated.
    out = normalise_headers([("k", b"v"), None, ("k2", b"v2")])
    assert out == {"k": "v", "k2": "v2"}


# ---------------------------------------------------------------------------
# invoke_handler
# ---------------------------------------------------------------------------


async def test_invoke_handler_sync_returning_none() -> None:
    calls: list[int] = []

    def handler(msg: Any, _receipt: Any) -> None:
        calls.append(1)

    await invoke_handler(handler, object(), object())  # type: ignore[arg-type]
    assert calls == [1]


async def test_invoke_handler_sync_returning_non_awaitable_is_ignored() -> None:
    # Current contract: a sync handler that returns a non-awaitable
    # (e.g. an int) has its return value silently dropped.
    def handler(_msg: Any, _receipt: Any) -> int:
        return 7

    result = await invoke_handler(handler, object(), object())  # type: ignore[arg-type]
    assert result is None


async def test_invoke_handler_async_is_awaited() -> None:
    calls: list[int] = []

    async def handler(_msg: Any, _receipt: Any) -> None:
        await asyncio.sleep(0)
        calls.append(1)

    await invoke_handler(handler, object(), object())  # type: ignore[arg-type]
    assert calls == [1]


async def test_invoke_handler_async_exception_propagates() -> None:
    async def handler(_msg: Any, _receipt: Any) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await invoke_handler(handler, object(), object())  # type: ignore[arg-type]
