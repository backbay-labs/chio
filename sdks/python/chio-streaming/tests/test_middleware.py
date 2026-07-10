"""Unit tests for :class:`chio_streaming.ChioConsumerMiddleware`.

Every test uses in-process fakes for the Kafka consumer / producer and
the :class:`chio_sdk.testing.MockChioClient`. No live broker or sidecar
is required.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_streaming import (
    RECEIPT_HEADER,
    VERDICT_HEADER,
    ChioConsumerConfig,
    ChioConsumerMiddleware,
    DLQRouter,
    build_middleware,
)
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import build_envelope

# ---------------------------------------------------------------------------
# In-process Kafka fakes
# ---------------------------------------------------------------------------


class FakeMessage:
    """Duck-typed ``confluent_kafka.Message``."""

    def __init__(
        self,
        *,
        topic: str,
        partition: int = 0,
        offset: int = 0,
        key: bytes | None = None,
        value: bytes = b"",
        headers: list[tuple[str, bytes]] | None = None,
        error: Any | None = None,
    ) -> None:
        self._topic = topic
        self._partition = partition
        self._offset = offset
        self._key = key
        self._value = value
        self._headers = headers
        self._error = error

    def topic(self) -> str:
        return self._topic

    def partition(self) -> int:
        return self._partition

    def offset(self) -> int:
        return self._offset

    def key(self) -> bytes | None:
        return self._key

    def value(self) -> bytes | None:
        return self._value

    def headers(self) -> list[tuple[str, bytes]] | None:
        return self._headers

    def error(self) -> Any | None:
        return self._error


class FakeConsumer:
    """In-memory consumer that yields queued ``FakeMessage``s."""

    def __init__(self, group_id: str = "group-1") -> None:
        self._queue: deque[FakeMessage] = deque()
        self._group_id = group_id
        self.commits: list[tuple[str, int, int]] = []
        self.closed = False

    def enqueue(self, message: FakeMessage) -> None:
        self._queue.append(message)

    def poll(self, timeout: float) -> FakeMessage | None:
        if self._queue:
            return self._queue.popleft()
        return None

    def commit(
        self,
        *,
        message: FakeMessage | None = None,
        asynchronous: bool = False,
    ) -> None:
        if message is None:
            return
        self.commits.append((message.topic(), message.partition(), message.offset()))

    def consumer_group_metadata(self) -> Any:
        return f"group-meta:{self._group_id}"

    def close(self) -> None:
        self.closed = True


class FakeProducer:
    """Transactional-looking in-memory producer.

    Buffers produces inside an open transaction and flushes them to
    ``produced`` only on ``commit_transaction``. ``abort_transaction``
    discards the buffer. This mirrors the at-most-once visibility
    confluent-kafka provides.
    """

    def __init__(
        self,
        *,
        fail_on_commit: bool = False,
        fail_on_produce_topics: set[str] | None = None,
        flush_undelivered: int = 0,
    ) -> None:
        self.produced: list[dict[str, Any]] = []
        self.committed_offsets: list[Any] = []
        self.transactions_begun = 0
        self.transactions_committed = 0
        self.transactions_aborted = 0
        self._flush_undelivered = flush_undelivered
        # Raw call count (every abort_transaction invocation), separate
        # from transactions_aborted which only increments when the fake
        # was in a transaction. confluent-kafka raises on an abort call
        # outside a tx; tracking raw calls surfaces double-abort bugs.
        self.abort_transaction_calls = 0
        self._in_tx = False
        self._buffer: list[dict[str, Any]] = []
        self._fail_on_commit = fail_on_commit
        self._fail_on_produce_topics = fail_on_produce_topics or set()

    # Transactional producer API -----------------------------------------

    def init_transactions(self, timeout: float = 10.0) -> None:  # pragma: no cover
        # Not invoked by the middleware (caller owns init).
        pass

    def begin_transaction(self) -> None:
        if self._in_tx:
            raise RuntimeError("transaction already open")
        self._in_tx = True
        self._buffer = []
        self.transactions_begun += 1

    def send_offsets_to_transaction(
        self,
        offsets: list[Any],
        group_metadata: Any,
        timeout: float,
    ) -> None:
        if not self._in_tx:
            raise RuntimeError("no open transaction")
        self.committed_offsets.append((list(offsets), group_metadata))

    def commit_transaction(self, timeout: float = 10.0) -> None:
        if not self._in_tx:
            raise RuntimeError("no open transaction")
        if self._fail_on_commit:
            # Broker aborted: discard buffer and rewind offsets.
            self._in_tx = False
            self._buffer = []
            self.committed_offsets = []
            self.transactions_aborted += 1
            raise RuntimeError("broker aborted transaction")
        self.produced.extend(self._buffer)
        self._buffer = []
        self._in_tx = False
        self.transactions_committed += 1

    def abort_transaction(self, timeout: float = 10.0) -> None:
        self.abort_transaction_calls += 1
        if not self._in_tx:
            return
        self._buffer = []
        # Offsets sent inside the transaction are also rolled back.
        self.committed_offsets = []
        self._in_tx = False
        self.transactions_aborted += 1

    # Produce -------------------------------------------------------------

    def produce(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> None:
        if topic in self._fail_on_produce_topics:
            raise RuntimeError(f"produce failed for topic={topic}")
        record = {
            "topic": topic,
            "value": value,
            "key": key,
            "headers": list(headers or []),
        }
        if self._in_tx:
            self._buffer.append(record)
        else:
            self.produced.append(record)

    def flush(self, timeout: float = 10.0) -> int:
        return self._flush_undelivered


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _cfg(**overrides: Any) -> ChioConsumerConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-evt",
        tool_server="kafka://local",
        scope_map={"orders": "events:consume:orders"},
        receipt_topic="chio-receipts",
        transactional=True,
        max_in_flight=4,
        poll_timeout=0.1,
        consumer_group_id="group-1",
    )
    base.update(overrides)
    return ChioConsumerConfig(**base)


def _fake_message(
    *,
    topic: str = "orders",
    partition: int = 0,
    offset: int = 7,
    value: bytes = b'{"id":1}',
    key: bytes | None = b"key-1",
    headers: list[tuple[str, bytes]] | None = None,
) -> FakeMessage:
    return FakeMessage(
        topic=topic,
        partition=partition,
        offset=offset,
        value=value,
        key=key,
        headers=headers or [("trace-id", b"abc")],
    )


def _build_middleware(
    *,
    chio_client: Any,
    dlq_topic: str = "chio-dlq",
    producer: FakeProducer | None = None,
    consumer: FakeConsumer | None = None,
    config: ChioConsumerConfig | None = None,
) -> tuple[ChioConsumerMiddleware, FakeConsumer, FakeProducer]:
    fake_consumer = consumer or FakeConsumer()
    fake_producer = producer or FakeProducer()
    mw = build_middleware(
        consumer=fake_consumer,
        producer=fake_producer,
        chio_client=chio_client,
        dlq_topic=dlq_topic,
        config=config or _cfg(),
    )
    return mw, fake_consumer, fake_producer


# ---------------------------------------------------------------------------
# Allow path
# ---------------------------------------------------------------------------


async def test_allow_path_runs_handler_publishes_receipt_and_commits() -> None:
    chio = allow_all()
    mw, consumer, producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message())

    handled: list[tuple[str, int]] = []

    async def handler(msg: Any, _receipt: Any) -> None:
        handled.append((msg.topic(), msg.offset()))

    outcome = await mw.poll_and_process(handler)

    assert outcome is not None
    assert outcome.allowed is True
    assert outcome.committed is True
    assert outcome.handler_error is None
    assert handled == [("orders", 7)]
    # request_id is derived from (topic, partition, offset) so non-transactional
    # consumers that redeliver between produce and commit still collide on
    # the same id for downstream dedupe.
    assert outcome.request_id == "chio-kafka-orders-0-7"
    # Allow path publishes a receipt envelope to the receipt topic.
    assert len(producer.produced) == 1
    produced = producer.produced[0]
    assert produced["topic"] == "chio-receipts"
    assert produced["key"] == outcome.request_id.encode("utf-8")
    envelope = json.loads(produced["value"].decode("utf-8"))
    assert envelope["verdict"] == "allow"
    # Offset + 1 is committed inside the transaction.
    assert producer.transactions_committed == 1
    assert producer.transactions_aborted == 0
    committed_offsets, _group = producer.committed_offsets[0]
    assert len(committed_offsets) == 1
    tp = committed_offsets[0]
    assert tp.topic == "orders" and tp.partition == 0 and tp.offset == 8


async def test_allow_path_sync_handler_is_awaited() -> None:
    chio = allow_all()
    mw, consumer, producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=11))

    called: list[int] = []

    def handler(msg: Any, _receipt: Any) -> None:
        called.append(msg.offset())

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert outcome.committed is True
    assert called == [11]


async def test_allow_path_handler_error_aborts_transaction() -> None:
    chio = allow_all()
    mw, consumer, producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=21))

    def handler(_msg: Any, _receipt: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.poll_and_process(handler)

    assert outcome is not None
    assert outcome.allowed is True
    assert outcome.committed is False
    assert isinstance(outcome.handler_error, RuntimeError)
    # Nothing made it through the transaction.
    assert producer.produced == []
    assert producer.transactions_begun == 1
    assert producer.transactions_committed == 0
    assert producer.transactions_aborted == 1


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # SystemExit / KeyboardInterrupt / CancelledError must propagate so
    # operators can shut the consumer down cleanly.
    chio = allow_all()
    mw, consumer, _producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=77))

    def handler(_msg: Any, _receipt: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.poll_and_process(handler)


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signal_aborts_open_transaction(shutdown_exc: type) -> None:
    # BaseException subclasses bypass the `except Exception` catch in
    # _handle_allow; the transaction must still be aborted in a finally
    # or the producer stays fenced on the next begin_transaction.
    chio = allow_all()
    mw, consumer, producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=91))

    def handler(_msg: Any, _receipt: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.poll_and_process(handler)

    assert producer.transactions_begun == 1
    assert producer.transactions_committed == 0
    assert producer.transactions_aborted == 1


# ---------------------------------------------------------------------------
# Deny path
# ---------------------------------------------------------------------------


async def test_deny_path_routes_to_dlq_and_commits_atomically() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw, consumer, producer = _build_middleware(chio_client=chio, dlq_topic="chio-dlq")
    consumer.enqueue(_fake_message(offset=17))

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.poll_and_process(handler)

    assert outcome is not None
    assert outcome.allowed is False
    assert outcome.committed is True
    assert outcome.dlq_record is not None
    assert outcome.dlq_record.topic == "chio-dlq"

    # Exactly one DLQ record produced (no receipt topic on deny).
    assert len(producer.produced) == 1
    assert producer.produced[0]["topic"] == "chio-dlq"
    payload = json.loads(producer.produced[0]["value"].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["guard"] == "scope-guard"

    header_dict = {n: v for n, v in producer.produced[0]["headers"]}
    assert header_dict[VERDICT_HEADER] == b"deny"
    assert RECEIPT_HEADER in header_dict

    # Transaction committed the offset.
    assert producer.transactions_committed == 1
    assert producer.transactions_aborted == 0


async def test_deny_path_handles_chio_sidecar_403() -> None:
    # The real sidecar raises ChioDeniedError on HTTP 403 rather than
    # returning a deny receipt; the middleware should synthesise one.
    chio = deny_all("forbidden", guard="kernel", raise_on_deny=True)
    mw, consumer, producer = _build_middleware(chio_client=chio, dlq_topic="chio-dlq")
    consumer.enqueue(_fake_message(offset=31))

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert outcome.allowed is False
    assert outcome.committed is True
    assert outcome.receipt.is_denied
    assert outcome.dlq_record is not None
    assert outcome.dlq_record.topic == "chio-dlq"


# ---------------------------------------------------------------------------
# Transaction atomicity
# ---------------------------------------------------------------------------


async def test_transaction_failure_rolls_back_offset_and_produce() -> None:
    """Simulate a broker-side commit failure.

    When ``commit_transaction`` raises, the buffered DLQ publish AND
    the staged offset must both roll back. The middleware re-raises so
    the caller can back off / restart; we assert the producer's state
    shows no committed records/offsets.
    """
    chio = deny_all("nope", raise_on_deny=False)
    producer = FakeProducer(fail_on_commit=True)
    mw, consumer, producer = _build_middleware(
        chio_client=chio, producer=producer, dlq_topic="chio-dlq"
    )
    consumer.enqueue(_fake_message(offset=99))

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="broker aborted transaction"):
        await mw.poll_and_process(handler)

    assert producer.produced == []  # nothing visible downstream
    assert producer.committed_offsets == []  # offset NOT advanced
    assert producer.transactions_committed == 0
    # Broker rejection path counts as an aborted transaction.
    assert producer.transactions_aborted == 1


# ---------------------------------------------------------------------------
# Sidecar unavailability
# ---------------------------------------------------------------------------


async def test_sidecar_error_raises_and_does_not_commit() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:  # pragma: no cover - raise path
            from chio_sdk.errors import ChioConnectionError

            raise ChioConnectionError("sidecar unreachable")

    mw, consumer, producer = _build_middleware(chio_client=FailingChio())
    consumer.enqueue(_fake_message(offset=4))

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run when sidecar is down")

    with pytest.raises(ChioStreamingError):
        await mw.poll_and_process(handler)

    # No transaction should have been opened.
    assert producer.transactions_begun == 0
    assert producer.produced == []
    assert consumer.commits == []


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            from chio_sdk.errors import ChioConnectionError

            raise ChioConnectionError("sidecar unreachable")

    # on_sidecar_error="deny" is only supported in non-transactional mode,
    # so the config must disable transactions for this path.
    cfg = _cfg(
        transactional=False,
        receipt_topic=None,
        consumer_group_id=None,
        on_sidecar_error="deny",
    )
    mw, consumer, producer = _build_middleware(chio_client=FailingChio(), config=cfg)
    consumer.enqueue(_fake_message(offset=12))

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    # DLQ publish + consumer commit happened.
    assert len(producer.produced) == 1
    assert producer.produced[0]["topic"] == "chio-dlq"
    assert consumer.commits == [("orders", 0, 12)]


# ---------------------------------------------------------------------------
# Non-transactional mode
# ---------------------------------------------------------------------------


async def test_non_transactional_commit_uses_consumer_commit() -> None:
    chio = allow_all()
    cfg = _cfg(transactional=False, receipt_topic=None, consumer_group_id=None)
    # Revalidate cfg since post_init enforces both fields only when
    # transactional=True. Re-run the dataclass constructor with the
    # overrides to confirm it accepts this combination.
    assert cfg.transactional is False

    mw, consumer, producer = _build_middleware(chio_client=chio, config=cfg)
    consumer.enqueue(_fake_message(offset=5))

    called: list[int] = []

    async def handler(msg: Any, _receipt: Any) -> None:
        called.append(msg.offset())

    outcome = await mw.poll_and_process(handler)

    assert outcome is not None
    assert outcome.allowed is True
    assert outcome.committed is True
    assert called == [5]
    # No transactions used in this mode.
    assert producer.transactions_begun == 0
    assert producer.transactions_committed == 0
    # Consumer commit was invoked directly.
    assert consumer.commits == [("orders", 0, 5)]


async def test_non_transactional_undelivered_flush_does_not_commit_offset() -> None:
    # confluent-kafka's flush() can return a non-zero count when the
    # broker stalls; committing the source offset in that case would
    # silently drop the receipt envelope and break auditability.
    chio = allow_all()
    cfg = _cfg(transactional=False, consumer_group_id=None)
    producer = FakeProducer(flush_undelivered=1)
    mw, consumer, _producer = _build_middleware(
        chio_client=chio,
        config=cfg,
        producer=producer,
    )
    consumer.enqueue(_fake_message(offset=9))

    async def handler(_msg: Any, _r: Any) -> None:
        return None

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    # acked=False because the source offset must not advance when the
    # receipt envelope did not durably land.
    assert outcome.committed is False
    assert consumer.commits == []
    assert isinstance(outcome.handler_error, ChioStreamingError)
    assert "undelivered" in str(outcome.handler_error)


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


async def test_backpressure_blocks_when_max_in_flight_reached() -> None:
    """When ``max_in_flight`` is 1, a second poll_and_process must wait
    for the first to release its slot before proceeding."""
    chio = allow_all()

    release = asyncio.Event()
    started_count = 0
    started_event = asyncio.Event()

    async def slow_handler(_msg: Any, _receipt: Any) -> None:
        nonlocal started_count
        started_count += 1
        started_event.set()
        await release.wait()

    cfg = _cfg(max_in_flight=1)
    mw, consumer, producer = _build_middleware(chio_client=chio, config=cfg)
    consumer.enqueue(_fake_message(offset=1))
    consumer.enqueue(_fake_message(offset=2))

    first = asyncio.create_task(mw.poll_and_process(slow_handler))
    await started_event.wait()
    assert mw.in_flight == 1
    assert started_count == 1

    # The second task must not enter the handler until the first
    # releases its slot. We give it a short window to try.
    second = asyncio.create_task(mw.poll_and_process(slow_handler))
    await asyncio.sleep(0.1)
    assert started_count == 1, "second handler ran before slot released"
    assert mw.in_flight == 1

    # Release the first handler; then the second can proceed.
    release.set()
    await asyncio.wait_for(first, timeout=2.0)
    await asyncio.wait_for(second, timeout=2.0)
    assert started_count == 2
    assert mw.in_flight == 0


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_config_requires_receipt_topic_when_transactional() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioConsumerConfig(
            capability_id="cap",
            tool_server="kafka",
            transactional=True,
            consumer_group_id="g",
        )


def test_config_requires_consumer_group_when_transactional() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioConsumerConfig(
            capability_id="cap",
            tool_server="kafka",
            transactional=True,
            receipt_topic="r",
        )


def test_config_rejects_fail_closed_with_transactional() -> None:
    # on_sidecar_error="deny" requires non-transactional mode because the
    # transactional commit path cannot safely synthesise a deny receipt.
    with pytest.raises(ChioStreamingConfigError):
        ChioConsumerConfig(
            capability_id="c",
            tool_server="kafka",
            transactional=True,
            receipt_topic="r",
            consumer_group_id="g",
            on_sidecar_error="deny",
        )


def test_config_rejects_empty_capability() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioConsumerConfig(
            capability_id="",
            tool_server="kafka",
            transactional=False,
        )


def test_config_rejects_zero_in_flight() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioConsumerConfig(
            capability_id="cap",
            tool_server="kafka",
            max_in_flight=0,
            transactional=False,
        )


def test_build_middleware_requires_router_or_topic() -> None:
    chio = allow_all()
    with pytest.raises(ChioStreamingConfigError):
        build_middleware(
            consumer=FakeConsumer(),
            producer=FakeProducer(),
            chio_client=chio,
            config=_cfg(),
        )


def test_build_middleware_with_explicit_router() -> None:
    chio = allow_all()
    router = DLQRouter(default_topic="dlq-explicit")
    mw = build_middleware(
        consumer=FakeConsumer(),
        producer=FakeProducer(),
        chio_client=chio,
        dlq_router=router,
        config=_cfg(),
    )
    assert isinstance(mw, ChioConsumerMiddleware)


# ---------------------------------------------------------------------------
# Scope resolution + parameter shape
# ---------------------------------------------------------------------------


async def test_scope_map_hit_uses_custom_tool_name() -> None:
    recorded: list[str] = []

    def policy(tool_name: str, _scope: dict, _ctx: dict) -> MockVerdict:
        recorded.append(tool_name)
        return MockVerdict.allow_verdict()

    chio = MockChioClient(policy=policy)
    cfg = _cfg(scope_map={"orders": "events:consume:orders-custom"})
    mw, consumer, _producer = _build_middleware(chio_client=chio, config=cfg)
    consumer.enqueue(_fake_message())

    async def handler(_msg: Any, _r: Any) -> None:
        return None

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert outcome.allowed is True
    assert recorded == ["events:consume:orders-custom"]


async def test_scope_map_miss_falls_back_to_default_prefix() -> None:
    recorded: list[str] = []

    def policy(tool_name: str, _scope: dict, _ctx: dict) -> MockVerdict:
        recorded.append(tool_name)
        return MockVerdict.allow_verdict()

    chio = MockChioClient(policy=policy)
    cfg = _cfg(scope_map={})
    mw, consumer, _producer = _build_middleware(chio_client=chio, config=cfg)
    consumer.enqueue(_fake_message(topic="payments"))

    async def handler(_msg: Any, _r: Any) -> None:
        return None

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert recorded == ["events:consume:payments"]


async def test_parameters_omit_body_but_carry_hash() -> None:
    captured: list[dict[str, Any]] = []

    def policy(_tool: str, _scope: dict, ctx: dict) -> MockVerdict:
        captured.append(ctx["parameters"])
        return MockVerdict.allow_verdict()

    chio = MockChioClient(policy=policy)
    mw, consumer, _producer = _build_middleware(chio_client=chio)
    consumer.enqueue(
        _fake_message(
            value=b'{"payload":"secret"}',
            headers=[("trace", b"t")],
        )
    )

    async def handler(_msg: Any, _r: Any) -> None:
        return None

    await mw.poll_and_process(handler)
    assert len(captured) == 1
    params = captured[0]
    # No body -- only metadata.
    assert "body_hash" in params and params["body_hash"] is not None
    assert "body" not in params
    assert params["body_length"] == len(b'{"payload":"secret"}')
    assert params["topic"] == "orders"
    assert params["headers"] == {"trace": "t"}


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


def test_close_is_idempotent() -> None:
    chio = allow_all()
    mw, consumer, _producer = _build_middleware(chio_client=chio)
    mw.close()
    mw.close()
    assert consumer.closed is True


async def test_poll_after_close_fails_without_polling_consumer() -> None:
    chio = allow_all()
    mw, consumer, _producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=88))
    mw.close()

    async def handler(_msg: Any, _receipt: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run after close")

    with pytest.raises(ChioStreamingError, match="closed"):
        await mw.poll_and_process(handler)

    assert len(consumer._queue) == 1


# ---------------------------------------------------------------------------
# Transactional DLQ / receipt produce failures inside the transaction
# ---------------------------------------------------------------------------


async def test_dlq_publish_failure_raises_and_does_not_ack() -> None:
    # Producing to the DLQ topic raises mid-transaction -> transaction
    # aborts, offset rolls back, caller sees the exception.
    chio = deny_all("nope", raise_on_deny=False)
    producer = FakeProducer(fail_on_produce_topics={"chio-dlq"})
    mw, consumer, producer = _build_middleware(
        chio_client=chio, producer=producer, dlq_topic="chio-dlq"
    )
    consumer.enqueue(_fake_message(offset=55))

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="produce failed"):
        await mw.poll_and_process(handler)

    assert producer.produced == []
    assert producer.committed_offsets == []
    assert producer.transactions_aborted == 1
    # Abort should run exactly once; the finally guard must not re-abort
    # an already-aborted transaction (confluent-kafka raises on that).
    assert producer.abort_transaction_calls == 1
    assert mw.in_flight == 0


async def test_receipt_publish_failure_aborts_transaction_and_does_not_ack() -> None:
    # Producing to the receipt topic raises -> transaction aborts,
    # offset does not advance. Handler error surfaces via the outcome.
    chio = allow_all()
    producer = FakeProducer(fail_on_produce_topics={"chio-receipts"})
    mw, consumer, producer = _build_middleware(
        chio_client=chio, producer=producer, dlq_topic="chio-dlq"
    )
    consumer.enqueue(_fake_message(offset=77))

    ran: list[int] = []

    async def handler(_m: Any, _r: Any) -> None:
        ran.append(1)

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    assert ran == [1]
    assert outcome.allowed is True
    assert outcome.committed is False
    assert isinstance(outcome.handler_error, RuntimeError)
    assert producer.produced == []
    assert producer.committed_offsets == []
    assert producer.transactions_aborted == 1
    assert mw.in_flight == 0


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    chio = allow_all()
    mw, consumer, producer = _build_middleware(chio_client=chio)
    consumer.enqueue(_fake_message(offset=3))

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.poll_and_process(handler)
    assert outcome is not None
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="orders",
        source_partition=0,
        source_offset=3,
    )
    produced = producer.produced[0]
    assert produced["topic"] == "chio-receipts"
    assert produced["value"] == expected.value
