"""Live NATS / JetStream integration tests for ``chio_streaming.nats``.

Same shape as ``tests/test_nats.py`` (in-memory fakes) but against a
real NATS server with JetStream enabled. Brought up by
``deploy/compose/streaming-compose.yml`` and gated by ``CHIO_INTEGRATION=1``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.testing import allow_all, deny_all

from chio_streaming.nats import (
    ChioNatsConsumerConfig,
    build_nats_middleware,
)


def _cfg(receipt_subject: str, **overrides: Any) -> ChioNatsConsumerConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-it-nats",
        tool_server="nats://it",
        scope_map={},
        receipt_subject=receipt_subject,
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioNatsConsumerConfig(**base)


async def _ensure_stream(js: Any, stream_name: str, subjects: list[str]) -> None:
    """Create or update a JetStream stream that captures ``subjects``."""
    from nats.js.api import StreamConfig  # type: ignore[import-not-found]

    cfg = StreamConfig(name=stream_name, subjects=subjects)
    try:
        await js.add_stream(cfg)
    except Exception:
        # Already exists with a different subject list -> update.
        await js.update_stream(cfg)


async def _pull_one(
    js: Any, stream_name: str, durable: str, subject: str
) -> Any:
    """Pull exactly one message from ``subject`` via a durable consumer."""
    sub = await js.pull_subscribe(subject=subject, durable=durable, stream=stream_name)
    msgs = await sub.fetch(1, timeout=2.0)
    assert msgs, f"no message delivered on subject={subject}"
    return msgs[0]


async def test_allow_publishes_receipt_and_acks_real_jetstream(
    nats_connection: Any, nats_unique_subject_root: str
) -> None:
    js = nats_connection.jetstream()

    work_subject = f"{nats_unique_subject_root}.tasks"
    receipt_subject = f"{nats_unique_subject_root}.receipts"
    dlq_subject = f"{nats_unique_subject_root}.dlq"

    work_stream = f"chio_it_work_{nats_unique_subject_root}"
    aux_stream = f"chio_it_aux_{nats_unique_subject_root}"

    await _ensure_stream(js, work_stream, [work_subject])
    # Receipts + DLQ share an aux stream so we can read them back to
    # verify the envelope shape.
    await _ensure_stream(js, aux_stream, [receipt_subject, dlq_subject])

    mw = build_nats_middleware(
        publisher=js,
        chio_client=allow_all(),
        config=_cfg(receipt_subject),
        dlq_subject=dlq_subject,
    )

    # Publish a unit of work with a stable Nats-Msg-Id so the request_id
    # is deterministic (mirrors test_request_id_is_deterministic_on_redelivery_*).
    await js.publish(work_subject, b'{"ok":true}', headers={"Nats-Msg-Id": "stable-it-1"})

    msg = await _pull_one(js, work_stream, durable="chio-it-work", subject=work_subject)

    seen_subjects: list[str] = []

    async def handler(m: Any, _receipt: Any) -> None:
        seen_subjects.append(m.subject)

    outcome = await mw.dispatch(msg, handler)

    assert outcome.allowed is True
    assert outcome.acked is True
    assert outcome.handler_error is None
    assert seen_subjects == [work_subject]
    assert outcome.request_id == "chio-nats-stable-it-1"

    # Receipt envelope is readable from the aux stream.
    receipt_sub = await js.pull_subscribe(
        subject=receipt_subject, durable="chio-it-rx", stream=aux_stream
    )
    rx = await receipt_sub.fetch(1, timeout=2.0)
    assert rx, "receipt was not published"
    envelope = json.loads(rx[0].data.decode("utf-8"))
    assert envelope["verdict"] == "allow"
    assert envelope["request_id"] == "chio-nats-stable-it-1"
    await rx[0].ack()


async def test_deny_publishes_dlq_and_acks_real_jetstream(
    nats_connection: Any, nats_unique_subject_root: str
) -> None:
    js = nats_connection.jetstream()

    work_subject = f"{nats_unique_subject_root}.tasks"
    receipt_subject = f"{nats_unique_subject_root}.receipts"
    dlq_subject = f"{nats_unique_subject_root}.dlq"

    work_stream = f"chio_it_work_{nats_unique_subject_root}"
    aux_stream = f"chio_it_aux_{nats_unique_subject_root}"

    await _ensure_stream(js, work_stream, [work_subject])
    await _ensure_stream(js, aux_stream, [receipt_subject, dlq_subject])

    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw = build_nats_middleware(
        publisher=js,
        chio_client=chio,
        config=_cfg(receipt_subject),
        dlq_subject=dlq_subject,
    )

    await js.publish(work_subject, b'{"evil":true}', headers={"Nats-Msg-Id": "stable-it-2"})
    msg = await _pull_one(js, work_stream, durable="chio-it-work-deny", subject=work_subject)

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler must not run on deny")

    outcome = await mw.dispatch(msg, handler)

    assert outcome.allowed is False
    assert outcome.acked is True

    # DLQ envelope was published; pull it from the aux stream.
    dlq_sub = await js.pull_subscribe(
        subject=dlq_subject, durable="chio-it-dlq", stream=aux_stream
    )
    dlq_msgs = await dlq_sub.fetch(1, timeout=2.0)
    assert dlq_msgs, "deny path did not publish a DLQ envelope"
    payload = json.loads(dlq_msgs[0].data.decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["source"]["topic"] == work_subject
    await dlq_msgs[0].ack()

    # Settle any background tasks before the connection drains.
    await asyncio.sleep(0)
