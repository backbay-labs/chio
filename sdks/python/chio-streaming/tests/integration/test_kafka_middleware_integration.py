"""Live Kafka (Redpanda) integration tests for ``chio_streaming.middleware``.

Mirrors the unit suite in ``tests/test_middleware.py`` but talks to a
real Kafka-compatible broker (Redpanda) brought up by
``deploy/compose/streaming-flink-compose.yml``. Gated by ``CHIO_INTEGRATION=1``
(see ``conftest.py``).

The dockerised Flink JobManager / TaskManager from the same compose
file are NOT exercised here; they exist as a UI / manual exploration
target. Flink integration coverage lives in
``test_flink_kafka_integration.py`` and uses PyFlink's local
mini-cluster in-process.

Each test creates fresh receipt + DLQ topics under unique names so
parallel test runs cannot collide. Topics are auto-deleted on
teardown via the ``kafka_topic_factory`` fixture.

Configured with ``transactional=False`` because Redpanda's
transactional surface is supported but the chio-streaming Kafka
middleware's transactional path requires the caller to drive
``init_transactions`` on a real producer; the at-least-once shape is
the simpler, more portable target for live integration coverage.
Transactional behaviour is exhaustively covered by the unit suite
which mocks the EOS protocol verbatim.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import pytest
from chio_sdk.testing import allow_all, deny_all

from chio_streaming import (
    ChioConsumerConfig,
    ChioConsumerMiddleware,
    DLQRouter,
    build_middleware,
)


def _require_confluent_kafka() -> Any:
    try:
        import confluent_kafka  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("confluent-kafka not installed; `uv sync --extra kafka`")
    return confluent_kafka


def _consumer_for(bootstrap: str, *, group_id: str) -> Any:
    confluent_kafka = _require_confluent_kafka()
    return confluent_kafka.Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": group_id,
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            # Short session/heartbeat so a forgotten close() does not
            # park a partition for the rest of the suite.
            "session.timeout.ms": 6000,
            "heartbeat.interval.ms": 2000,
        }
    )


def _producer_for(bootstrap: str) -> Any:
    confluent_kafka = _require_confluent_kafka()
    # Non-transactional. The middleware's transactional path uses
    # init_transactions() + send_offsets_to_transaction; the chio test
    # plan covers it with mocks. Live coverage targets the simpler
    # at-least-once shape.
    return confluent_kafka.Producer(
        {
            "bootstrap.servers": bootstrap,
            "enable.idempotence": True,
            "linger.ms": 0,
        }
    )


def _wait_for_assignment(consumer: Any, topic: str, timeout: float = 10.0) -> None:
    """Poll until the consumer is assigned at least one partition.

    confluent-kafka's ``subscribe`` is async; the first ``poll`` after
    subscribe usually returns ``None`` while the group joins. We use
    a tiny poll timeout (0.05s) so the loop drains group-join events
    without consuming application messages: any record returned here
    would be silently discarded and would invalidate downstream
    assertions about offsets.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = consumer.poll(0.05)
        # If a message did sneak in (very rare; the test produces
        # *after* assignment), seek back so the middleware sees it.
        if msg is not None and msg.error() is None:
            from confluent_kafka import TopicPartition

            consumer.seek(TopicPartition(msg.topic(), msg.partition(), msg.offset()))
        assignment = consumer.assignment()
        if any(tp.topic == topic for tp in assignment):
            return
    raise AssertionError(f"consumer never assigned partitions for topic={topic}")


def _produce_one(producer: Any, topic: str, value: bytes, *, key: bytes | None = None) -> None:
    producer.produce(topic, value=value, key=key)
    # A finite flush keeps the test from hanging the suite if the
    # broker is wedged. 10s is generous; a healthy Redpanda flushes in
    # single-digit ms.
    remaining = producer.flush(10.0)
    assert remaining == 0, f"produce flush left {remaining} message(s) undelivered"


def _read_one(consumer: Any, topic: str, *, timeout: float = 10.0) -> Any:
    """Poll the receipt / DLQ topic until one message appears or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = consumer.poll(0.5)
        if msg is None:
            continue
        if msg.error() is not None:
            raise AssertionError(f"consumer error: {msg.error()}")
        if msg.topic() == topic:
            return msg
    raise AssertionError(f"no message arrived on topic={topic} within {timeout}s")


def _cfg(*, source_topic: str, receipt_topic: str, group_id: str) -> ChioConsumerConfig:
    # transactional=False because the test exercises the at-least-once
    # path. The middleware's transactional path is unit-tested with a
    # mocked producer; reaching it live would require the caller to
    # call init_transactions() and provide a transactional.id, which
    # the README documents at the call site rather than here.
    return ChioConsumerConfig(
        capability_id="cap-it-kafka",
        tool_server="kafka://it",
        scope_map={source_topic: f"events:consume:{source_topic}"},
        receipt_topic=receipt_topic,
        transactional=False,
        max_in_flight=4,
        # Generous poll timeout so the first call after group-join can
        # fetch records without spinning the test loop.
        poll_timeout=5.0,
        produce_timeout=5.0,
    )


async def _poll_until_outcome(
    mw: ChioConsumerMiddleware,
    handler: Any,
    *,
    attempts: int = 6,
) -> Any:
    """Poll the middleware until it returns an outcome (or runs out).

    confluent-kafka may return None on the first one or two polls
    while the consumer warms up its fetch buffers; retrying keeps the
    test from being flaky on a slow runner.
    """
    last = None
    for _ in range(attempts):
        last = await mw.poll_and_process(handler)
        if last is not None:
            return last
    return last


async def test_allow_publishes_receipt_to_real_kafka(
    kafka_bootstrap: str,
    kafka_topic_factory: Any,
) -> None:
    source_topic = kafka_topic_factory("orders")
    receipt_topic = kafka_topic_factory("receipts")
    dlq_topic = kafka_topic_factory("dlq")
    group_id = f"chio-it-allow-{uuid.uuid4().hex[:8]}"

    consumer = _consumer_for(kafka_bootstrap, group_id=group_id)
    producer = _producer_for(kafka_bootstrap)

    # Separate consumer just to read the receipt topic back. Using the
    # middleware's consumer would race the offset commit and risk
    # picking the receipt up via the same group's poll() loop.
    receipt_consumer = _consumer_for(
        kafka_bootstrap, group_id=f"chio-it-receipt-reader-{uuid.uuid4().hex[:8]}"
    )

    try:
        consumer.subscribe([source_topic])
        receipt_consumer.subscribe([receipt_topic])
        _wait_for_assignment(consumer, source_topic)
        _wait_for_assignment(receipt_consumer, receipt_topic)

        # Publish one event for the middleware to evaluate.
        _produce_one(producer, source_topic, b'{"id":1,"intent":"ok"}', key=b"k1")

        mw = build_middleware(
            consumer=consumer,
            producer=producer,
            chio_client=allow_all(),
            dlq_topic=dlq_topic,
            config=_cfg(
                source_topic=source_topic,
                receipt_topic=receipt_topic,
                group_id=group_id,
            ),
        )

        seen: list[tuple[str, int]] = []

        async def handler(msg: Any, _receipt: Any) -> None:
            seen.append((msg.topic(), msg.offset()))

        outcome = await _poll_until_outcome(mw, handler)

        assert outcome is not None
        assert outcome.allowed is True
        assert outcome.acked is True
        assert outcome.handler_error is None
        assert seen == [(source_topic, 0)]
        # request_id derives from (topic, partition, offset); the
        # READMEd dedupe contract.
        assert outcome.request_id == f"chio-kafka-{source_topic}-0-0"

        # Receipt envelope should now be on the receipt topic.
        receipt_msg = _read_one(receipt_consumer, receipt_topic)
        envelope = json.loads(receipt_msg.value().decode("utf-8"))
        assert envelope["verdict"] == "allow"
        assert envelope["request_id"] == outcome.request_id
        assert receipt_msg.key() == outcome.request_id.encode("utf-8")
    finally:
        consumer.close()
        receipt_consumer.close()


async def test_deny_publishes_dlq_to_real_kafka(
    kafka_bootstrap: str,
    kafka_topic_factory: Any,
) -> None:
    source_topic = kafka_topic_factory("orders")
    receipt_topic = kafka_topic_factory("receipts")
    dlq_topic = kafka_topic_factory("dlq")
    group_id = f"chio-it-deny-{uuid.uuid4().hex[:8]}"

    consumer = _consumer_for(kafka_bootstrap, group_id=group_id)
    producer = _producer_for(kafka_bootstrap)
    dlq_consumer = _consumer_for(
        kafka_bootstrap, group_id=f"chio-it-dlq-reader-{uuid.uuid4().hex[:8]}"
    )

    try:
        consumer.subscribe([source_topic])
        dlq_consumer.subscribe([dlq_topic])
        _wait_for_assignment(consumer, source_topic)
        _wait_for_assignment(dlq_consumer, dlq_topic)

        _produce_one(producer, source_topic, b'{"id":2,"intent":"evil"}', key=b"k2")

        chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
        mw = build_middleware(
            consumer=consumer,
            producer=producer,
            chio_client=chio,
            dlq_router=DLQRouter(default_topic=dlq_topic),
            config=_cfg(
                source_topic=source_topic,
                receipt_topic=receipt_topic,
                group_id=group_id,
            ),
        )

        async def handler(_msg: Any, _r: Any) -> None:  # pragma: no cover
            pytest.fail("handler must not run on deny")

        outcome = await _poll_until_outcome(mw, handler)

        assert outcome is not None
        assert outcome.allowed is False
        assert outcome.acked is True
        assert outcome.dlq_record is not None
        assert outcome.dlq_record.topic == dlq_topic

        # DLQ envelope landed on the DLQ topic.
        dlq_msg = _read_one(dlq_consumer, dlq_topic)
        payload = json.loads(dlq_msg.value().decode("utf-8"))
        assert payload["verdict"] == "deny"
        assert payload["reason"] == "missing scope"
        assert payload["guard"] == "scope-guard"
        assert payload["receipt"]["decision"]["verdict"] == "deny"
    finally:
        consumer.close()
        dlq_consumer.close()


async def test_request_id_deterministic_on_redelivery_real_kafka(
    kafka_bootstrap: str,
    kafka_topic_factory: Any,
) -> None:
    """Same (topic, partition, offset) -> same request_id.

    Two sequential consumer sessions over the same partition are the
    portable proxy for "broker redelivered the source": the test never
    commits an offset so each fresh group rejoins at earliest and sees
    the same record at the same offset. Downstream dedupers must
    collide on the same id.
    """
    source_topic = kafka_topic_factory("orders")
    receipt_topic = kafka_topic_factory("receipts")
    dlq_topic = kafka_topic_factory("dlq")

    producer = _producer_for(kafka_bootstrap)
    _produce_one(producer, source_topic, b'{"id":3}', key=b"k3")

    request_ids: list[str] = []
    for _round in range(2):
        group_id = f"chio-it-redeliver-{uuid.uuid4().hex[:8]}"
        consumer = _consumer_for(kafka_bootstrap, group_id=group_id)
        try:
            consumer.subscribe([source_topic])
            _wait_for_assignment(consumer, source_topic)

            mw = build_middleware(
                consumer=consumer,
                producer=producer,
                chio_client=allow_all(),
                dlq_topic=dlq_topic,
                config=_cfg(
                    source_topic=source_topic,
                    receipt_topic=receipt_topic,
                    group_id=group_id,
                ),
            )

            async def handler(_msg: Any, _r: Any) -> None:
                return None

            outcome = await _poll_until_outcome(mw, handler)
            assert outcome is not None, "expected a polled message"
            request_ids.append(outcome.request_id)
        finally:
            consumer.close()

    assert len(request_ids) == 2
    assert request_ids[0] == request_ids[1], (
        f"redelivery should produce the same request_id, got {request_ids!r}"
    )
