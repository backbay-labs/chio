"""Live Redis Streams integration tests for ``chio_streaming.redis_streams``.

These exercise the same API shape as ``tests/test_redis_streams.py``
(unit tests with an in-memory double) but talk to a real Redis. The
broker is brought up by ``deploy/compose/streaming-compose.yml`` and gated by
``CHIO_INTEGRATION=1`` -- see ``conftest.py``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.testing import allow_all, deny_all

from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    RedisStreamEntry,
    build_redis_streams_middleware,
)

GROUP = "chio-it-group"
CONSUMER = "chio-it-consumer"
RECEIPT_STREAM = "chio-it-receipts"
DLQ_STREAM = "chio-it-dlq"


def _cfg(**overrides: Any) -> ChioRedisStreamsConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-it-redis",
        tool_server="redis://it",
        group_name=GROUP,
        scope_map={},
        receipt_stream=RECEIPT_STREAM,
        receipt_maxlen=1_000,
        dlq_maxlen=1_000,
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioRedisStreamsConfig(**base)


async def _ensure_group(client: Any, stream: str) -> None:
    """Create the consumer group, MKSTREAM if the stream does not exist yet."""
    try:
        await client.xgroup_create(name=stream, groupname=GROUP, id="0", mkstream=True)
    except Exception as exc:  # noqa: BLE001 -- redis raises a typed error here
        # BUSYGROUP means the group already exists; everything else is fatal.
        if "BUSYGROUP" not in str(exc):
            raise


async def _read_one(client: Any, stream: str) -> tuple[str, dict[bytes, bytes]]:
    """Read exactly one pending entry via XREADGROUP."""
    resp = await client.xreadgroup(
        groupname=GROUP,
        consumername=CONSUMER,
        streams={stream: ">"},
        count=1,
        block=2_000,
    )
    assert resp, f"no entry delivered on stream={stream}"
    _, entries = resp[0]
    assert entries, "XREADGROUP returned an empty entry list"
    entry_id, fields = entries[0]
    return entry_id.decode("utf-8"), fields


async def test_allow_publishes_receipt_and_xacks_real_redis(
    redis_client: Any, redis_unique_stream: str
) -> None:
    stream = redis_unique_stream
    await _ensure_group(redis_client, stream)

    mw = build_redis_streams_middleware(
        client=redis_client,
        chio_client=allow_all(),
        config=_cfg(),
        dlq_stream=DLQ_STREAM,
    )

    # Publish a single source entry, then read it back via XREADGROUP so
    # the entry lands in our PEL (otherwise XACK would be a no-op).
    await redis_client.xadd(stream, {b"payload": b'{"ok":true}', b"trace": b"t"})
    entry_id, fields = await _read_one(redis_client, stream)

    seen: list[RedisStreamEntry] = []

    async def handler(entry: RedisStreamEntry, _receipt: Any) -> None:
        seen.append(entry)

    outcome = await mw.dispatch(
        stream=stream,
        entry_id=entry_id,
        fields=fields,
        handler=handler,
    )

    assert outcome.allowed is True
    assert outcome.acked is True, "XACK should have removed the entry from the PEL"
    assert outcome.handler_error is None
    assert seen and seen[0].entry_id == entry_id

    # PEL is empty: XPENDING summary's first element is the count.
    pending = await redis_client.xpending(stream, GROUP)
    # redis-py returns either a list (legacy) or a dict (newer); handle both.
    if isinstance(pending, dict):
        assert pending.get("pending", 0) == 0
    else:
        assert pending[0] == 0

    # Receipt landed on the receipt stream with a parseable envelope.
    rec = await redis_client.xrevrange(RECEIPT_STREAM, count=1)
    assert rec, "no receipt entry written"
    _rid, rfields = rec[0]
    payload = json.loads(rfields[b"payload"].decode("utf-8"))
    assert payload["verdict"] == "allow"
    assert payload["request_id"] == outcome.request_id


async def test_deny_publishes_dlq_and_xacks_real_redis(
    redis_client: Any, redis_unique_stream: str
) -> None:
    stream = redis_unique_stream
    await _ensure_group(redis_client, stream)

    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw = build_redis_streams_middleware(
        client=redis_client,
        chio_client=chio,
        config=_cfg(),
        dlq_stream=DLQ_STREAM,
    )

    await redis_client.xadd(stream, {b"payload": b'{"evil":true}'})
    entry_id, fields = await _read_one(redis_client, stream)

    async def handler(_e: RedisStreamEntry, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler must not run on deny")

    outcome = await mw.dispatch(
        stream=stream,
        entry_id=entry_id,
        fields=fields,
        handler=handler,
    )

    assert outcome.allowed is False
    assert outcome.acked is True
    # PEL drained.
    pending = await redis_client.xpending(stream, GROUP)
    if isinstance(pending, dict):
        assert pending.get("pending", 0) == 0
    else:
        assert pending[0] == 0

    # DLQ entry written with a deny envelope referencing the source entry id.
    dlq = await redis_client.xrevrange(DLQ_STREAM, count=1)
    assert dlq, "no DLQ entry written"
    _did, dfields = dlq[0]
    payload = json.loads(dfields[b"payload"].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["metadata"]["redis_entry_id"] == entry_id


async def test_request_id_deterministic_on_redelivery_real_redis(
    redis_client: Any, redis_unique_stream: str
) -> None:
    """XCLAIM-style redelivery: same stream + entry_id -> same request_id."""
    stream = redis_unique_stream
    await _ensure_group(redis_client, stream)

    mw = build_redis_streams_middleware(
        client=redis_client,
        chio_client=allow_all(),
        config=_cfg(),
        dlq_stream=DLQ_STREAM,
    )

    await redis_client.xadd(stream, {b"k": b"v"})
    entry_id, fields = await _read_one(redis_client, stream)

    async def handler(_e: RedisStreamEntry, _r: Any) -> None:
        return None

    first = await mw.dispatch(stream=stream, entry_id=entry_id, fields=fields, handler=handler)
    # Simulate a redelivery: dispatch again with the SAME entry id.
    second = await mw.dispatch(stream=stream, entry_id=entry_id, fields=fields, handler=handler)

    assert first.request_id == second.request_id
    # Allow the event loop to settle any background bookkeeping.
    await asyncio.sleep(0)
