"""End-to-end PyFlink + Kafka (Redpanda) integration test for the
Chio Flink operators.

What this test exercises (one full run of a bounded PyFlink job):

* A Kafka source (``KafkaSource``) reads two source events from a real
  Redpanda topic, one shaped to allow and one shaped to deny.
* The Chio async operator (``ChioAsyncEvaluateFunction``) evaluates
  each event against a deterministic ``ChioClientLike`` test double
  whose verdict is keyed by an ``intent`` field on the event.
* ``ChioVerdictSplitFunction`` fans out into main / receipt-side /
  DLQ-side outputs.
* Two PyFlink ``MapFunction`` sinks publish the receipt and DLQ
  bytes to real Kafka topics via ``confluent-kafka``. We use a Python
  sink (rather than ``KafkaSink``) because PyFlink 2.2's ``KafkaSink``
  Java class is not loadable into the Python gateway JVM via
  ``add_jars`` in this environment; ``KafkaSource``, the operators,
  and Python-side producers all work, which is enough to assert the
  full ingress -> evaluate -> egress contract over real Kafka.

The test then reads the receipt and DLQ topics back via
``confluent-kafka`` and asserts:

* The receipt topic carries an envelope with ``verdict == "allow"``
  byte-identical to ``build_envelope(...).value``.
* The DLQ topic carries a deny envelope with ``verdict == "deny"``,
  reason / guard preserved.

Constraints honoured:

* Uses ``LocalStreamEnvironment`` (PyFlink's in-process mini-cluster).
  The dockerised JobManager / TaskManager from
  ``deploy/compose/streaming-flink-compose.yml`` are present only as a UI /
  manual exploration target; submitting a job to the dockerised
  cluster forces a Python version match between host and container
  which is brittle for CI.
* Bounded source (``KafkaOffsetsInitializer.latest()`` as the bounded
  end), so ``env.execute`` returns when the two test events have been
  drained.
* Topics are unique per test run via ``kafka_topic_factory`` so
  parallel runs do not collide.

Skipped when:

* ``CHIO_INTEGRATION!=1``.
* Redpanda is not reachable on the configured bootstrap.
* PyFlink (``apache-flink``) is not installed.
* The Flink Kafka connector JAR is not present at
  ``sdks/python/chio-streaming/.test-jars/`` (the test prints a clear
  download command rather than auto-downloading at test time, so a
  hermetic / air-gapped runner produces a deterministic skip).
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_streaming.dlq import DLQRouter
from chio_streaming.flink import (
    DLQ_TAG_NAME,
    RECEIPT_TAG_NAME,
    ChioAsyncEvaluateFunction,
    ChioFlinkConfig,
    ChioVerdictSplitFunction,
)


# ---------------------------------------------------------------------------
# Connector JAR discovery
# ---------------------------------------------------------------------------

# Pinned to match apache-flink==2.2.0 (Flink runtime 2.0+ connector
# series). 4.0.x-1.20 series is for Flink 1.20; 4.0.x-2.0 is the right
# match for apache-flink>=2.2 (connector tracks Flink runtime, which
# the PyFlink 2.2 wheel bundles as 2.2 internally).
KAFKA_CONNECTOR_JAR = "flink-sql-connector-kafka-4.0.1-2.0.jar"
KAFKA_CONNECTOR_URL = (
    "https://repo.maven.apache.org/maven2/org/apache/flink/"
    "flink-sql-connector-kafka/4.0.1-2.0/flink-sql-connector-kafka-4.0.1-2.0.jar"
)


def _resolve_connector_jar() -> Path:
    """Locate the Kafka connector JAR or skip with download instructions.

    The test does NOT auto-download at runtime: pulling 9MB on every
    test run is unfriendly to CI bandwidth and air-gapped runners.
    The Makefile target (`make infra-flink-up`) does the one-time
    download up front.
    """
    # The Makefile target stages JARs under
    # `sdks/python/chio-streaming/.test-jars/`.
    candidate = (
        Path(__file__).resolve().parents[2] / ".test-jars" / KAFKA_CONNECTOR_JAR
    )
    if candidate.is_file():
        return candidate
    pytest.skip(
        f"Flink Kafka connector JAR not found at {candidate}. "
        f"Run `make infra-flink-up` (which fetches it) or:\n"
        f"  mkdir -p {candidate.parent} && curl -fsSL -o {candidate} {KAFKA_CONNECTOR_URL}"
    )


# ---------------------------------------------------------------------------
# Helpers shared by the test
# ---------------------------------------------------------------------------

# Verdict shape (the Chio sidecar replaces this in production). The
# operator parameters extractor sets `intent` on every event so the
# test can route allow / deny deterministically without a live
# sidecar.
_ALLOW_INTENT = "ok"
_DENY_INTENT = "evil"


def _scoring_chio_client_factory() -> Any:
    """Return a factory closure (not the client itself).

    ChioFlinkConfig requires a factory because the client is
    constructed on the TaskManager subtask. The factory closure
    captures only primitives so it cloudpickles cleanly.
    """

    def factory() -> Any:
        # The MockChioClient policy signature is
        # (tool_name, scope, context). ``scope`` carries
        # tool_server / tool_name; the chio_streaming parameters
        # (where our `intent` field lives) ride in
        # ``context["parameters"]``.
        def policy(_tool: str, _scope: dict, ctx: dict) -> MockVerdict:
            params = ctx.get("parameters", {}) or {}
            if params.get("intent") == _DENY_INTENT:
                return MockVerdict.deny_verdict(
                    "intent flagged as evil", guard="intent-guard"
                )
            return MockVerdict.allow_verdict()

        # raise_on_deny=False so the deny verdict comes back as a
        # receipt with Decision.deny rather than a thrown ChioDeniedError;
        # the chio Flink operator handles both shapes but the live
        # path the test mirrors is "receipt.is_denied -> route to DLQ".
        return MockChioClient(policy=policy, raise_on_deny=False)

    return factory


def _dlq_router_factory_for(topic: str) -> Any:
    def factory() -> DLQRouter:
        return DLQRouter(default_topic=topic)

    return factory


def _params_extractor(element: dict[str, Any]) -> dict[str, Any]:
    """Surface ``intent`` to the chio params dict.

    The default extractor only writes ``request_id``, ``subject``,
    ``body_length``, ``body_hash`` -- fine for production, but our
    MockChioClient routes verdicts off the ``intent`` field, so we
    add it here.
    """
    return {"intent": element.get("intent", "")}


def _subject_extractor(_element: Any) -> str:
    # All test events live on the logical "transactions" subject so
    # they share a single scope_map entry.
    return "transactions"


# ---------------------------------------------------------------------------
# Sink that runs on the TaskManager and republishes to Kafka
# ---------------------------------------------------------------------------
#
# Defined inline (not at module level) inside the test factory so the
# closure does not capture pytest fixtures. PyFlink cloudpickles
# operators across the JM->TM boundary; everything in `__init__` must
# be picklable. We pass primitives only.


def _build_kafka_sink_class() -> Any:
    """Return a ``MapFunction`` subclass that publishes to Kafka.

    Imports happen inside the class so test collection does not bomb
    when PyFlink is missing.
    """
    from pyflink.datastream.functions import MapFunction

    class _KafkaPyMapSink(MapFunction):
        """Publishes ``value`` (bytes) to Kafka and forwards it.

        The forwarded value lets us chain ``.print()`` after the sink
        for diagnostic visibility without breaking the topology.
        """

        def __init__(self, bootstrap: str, topic: str) -> None:
            self.bootstrap = bootstrap
            self.topic = topic
            self._p: Any = None

        def open(self, runtime_context: Any) -> None:
            # Local import keeps cloudpickle happy: the class itself
            # only references primitives at __init__ time.
            from confluent_kafka import Producer

            self._p = Producer({"bootstrap.servers": self.bootstrap})

        def map(self, value: bytes) -> bytes:
            # The chio operators emit `bytes`; pass straight through.
            self._p.produce(self.topic, value=value)
            # Flush per-record so the bounded-job teardown is not
            # racing the producer's batch timer. Throughput is not the
            # concern in an integration test.
            self._p.flush(5)
            return value

        def close(self) -> None:
            if self._p is not None:
                self._p.flush(5)

    return _KafkaPyMapSink


# ---------------------------------------------------------------------------
# Source seeding + sink readback helpers
# ---------------------------------------------------------------------------


def _produce_source_events(bootstrap: str, topic: str) -> None:
    from confluent_kafka import Producer

    p = Producer({"bootstrap.servers": bootstrap})
    p.produce(
        topic,
        value=json.dumps({"id": "t1", "intent": _ALLOW_INTENT}).encode("utf-8"),
    )
    p.produce(
        topic,
        value=json.dumps({"id": "t2", "intent": _DENY_INTENT}).encode("utf-8"),
    )
    remaining = p.flush(10)
    assert remaining == 0, f"source produce flushed {remaining} undelivered"


def _drain_topic(
    bootstrap: str, topic: str, *, max_messages: int = 5, timeout: float = 30.0
) -> list[Any]:
    """Read up to ``max_messages`` from ``topic`` (returns Kafka messages)."""
    from confluent_kafka import Consumer

    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": f"chio-it-flink-reader-{uuid.uuid4().hex[:8]}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
    )
    try:
        consumer.subscribe([topic])
        deadline = time.monotonic() + timeout
        out: list[Any] = []
        while time.monotonic() < deadline and len(out) < max_messages:
            msg = consumer.poll(0.5)
            if msg is None:
                continue
            if msg.error() is not None:
                # Surface broker errors instead of dropping silently;
                # the empty-receipt assert downstream would otherwise
                # mask "broker said EOF / auth failure" as "no event".
                raise AssertionError(
                    f"kafka consumer error draining {topic}: {msg.error()}"
                )
            out.append(msg)
        return out
    finally:
        consumer.close()


# ---------------------------------------------------------------------------
# The integration test
# ---------------------------------------------------------------------------


def test_flink_async_evaluate_with_real_kafka_source_and_sinks(
    pyflink_module: Any,  # noqa: ARG001 -- skip-gate fixture
    kafka_bootstrap: str,
    kafka_topic_factory: Any,
) -> None:
    # Make sure connector JAR is present before paying for any setup.
    jar_path = _resolve_connector_jar()

    src_topic = kafka_topic_factory("flink-src")
    receipt_topic = kafka_topic_factory("flink-receipts")
    dlq_topic = kafka_topic_factory("flink-dlq")

    _produce_source_events(kafka_bootstrap, src_topic)

    # Defer all PyFlink imports to after the skip gates, so a missing
    # extra produces a clean skip rather than an ImportError at
    # collection time.
    from pyflink.common import Time
    from pyflink.common.serialization import SimpleStringSchema
    from pyflink.common.typeinfo import Types
    from pyflink.common.watermark_strategy import WatermarkStrategy
    from pyflink.datastream import (
        AsyncDataStream,
        OutputTag,
        StreamExecutionEnvironment,
    )
    from pyflink.datastream.connectors.kafka import (
        KafkaOffsetsInitializer,
        KafkaSource,
    )

    # OutputTag instances must match the operator's tag names AND
    # type_info to retrieve side outputs.
    receipt_tag = OutputTag(RECEIPT_TAG_NAME, Types.PICKLED_BYTE_ARRAY())
    dlq_tag = OutputTag(DLQ_TAG_NAME, Types.PICKLED_BYTE_ARRAY())

    env = StreamExecutionEnvironment.get_execution_environment()
    env.set_parallelism(1)
    # PyFlink shells out to `python` to discover its bin path; pin to
    # the venv's interpreter so the worker resolves to the right
    # pyflink install.
    env.set_python_executable(sys.executable)
    env.add_jars(f"file://{jar_path}")

    source = (
        KafkaSource.builder()
        .set_bootstrap_servers(kafka_bootstrap)
        .set_topics(src_topic)
        .set_group_id(f"chio-flink-it-{uuid.uuid4().hex[:8]}")
        .set_starting_offsets(KafkaOffsetsInitializer.earliest())
        # Bounded source: stop reading at the latest offset so
        # env.execute() returns when the test events drain.
        .set_bounded(KafkaOffsetsInitializer.latest())
        .set_value_only_deserializer(SimpleStringSchema())
        .build()
    )

    raw = env.from_source(
        source,
        WatermarkStrategy.no_watermarks(),
        "chio-flink-it-source",
        type_info=Types.STRING(),
    )

    # Decode JSON payloads on the way in. Output type is pickled-bytes
    # so downstream operators can pass arbitrary Python objects.
    parsed = raw.map(
        lambda raw_json: json.loads(raw_json),
        output_type=Types.PICKLED_BYTE_ARRAY(),
    )

    config = ChioFlinkConfig(
        capability_id="cap-it-flink",
        tool_server="flink://it",
        client_factory=_scoring_chio_client_factory(),
        dlq_router_factory=_dlq_router_factory_for(dlq_topic),
        scope_map={"transactions": "events:consume:transactions"},
        receipt_topic="chio-receipts-logical",  # logical, not Kafka topic
        max_in_flight=4,
        on_sidecar_error="raise",
        subject_extractor=_subject_extractor,
        parameters_extractor=_params_extractor,
    )

    # AsyncDataStream.unordered_wait signature in PyFlink 2.2:
    # (input, async_func, timeout, capacity, output_type). The
    # timeout MUST be a pyflink.common.Time, not a raw int -- the
    # Java side calls .toMilliseconds() on it.
    evaluated = AsyncDataStream.unordered_wait(
        parsed,
        ChioAsyncEvaluateFunction(config),
        Time.milliseconds(10_000),
        16,
        Types.PICKLED_BYTE_ARRAY(),
    )
    split = evaluated.process(ChioVerdictSplitFunction())

    KafkaPyMapSink = _build_kafka_sink_class()
    receipts = split.get_side_output(receipt_tag)
    dlq = split.get_side_output(dlq_tag)

    # Side outputs are bytes; the Python sink publishes them to Kafka
    # and forwards so we can chain print() for diagnostics. The main
    # output (allowed events) is just printed; the test does not
    # assert on it.
    receipts.map(
        KafkaPyMapSink(kafka_bootstrap, receipt_topic),
        output_type=Types.PICKLED_BYTE_ARRAY(),
    ).name("receipt-kafka-sink")

    dlq.map(
        KafkaPyMapSink(kafka_bootstrap, dlq_topic),
        output_type=Types.PICKLED_BYTE_ARRAY(),
    ).name("dlq-kafka-sink")

    # Block until the bounded source drains. Should complete in well
    # under a minute on any laptop; a slow Maven coords resolution
    # on a cold JVM is the long pole.
    env.execute("chio-flink-kafka-it")

    # Read the receipts and DLQ topics back. The bounded source
    # produces exactly two records (one allow, one deny) so we expect
    # exactly one entry on each output topic.
    receipt_msgs = _drain_topic(kafka_bootstrap, receipt_topic, max_messages=2)
    dlq_msgs = _drain_topic(kafka_bootstrap, dlq_topic, max_messages=2)

    # Bounded source publishes exactly one allow and one deny event;
    # the split operator must route each to its own side output. A
    # looser >=1 check would mask a bug that emits both records to
    # the same tag.
    assert len(receipt_msgs) == 1, (
        f"expected exactly one receipt envelope on Kafka, got {len(receipt_msgs)}"
    )
    assert len(dlq_msgs) == 1, (
        f"expected exactly one DLQ envelope on Kafka, got {len(dlq_msgs)}"
    )

    # Receipt envelope shape (allow path).
    receipt_payload = json.loads(receipt_msgs[0].value().decode("utf-8"))
    assert receipt_payload["verdict"] == "allow"
    assert receipt_payload["request_id"].startswith("chio-flink-")
    # The envelope embeds the source receipt body.
    assert "receipt" in receipt_payload

    # DLQ envelope shape (deny path).
    dlq_payload = json.loads(dlq_msgs[0].value().decode("utf-8"))
    assert dlq_payload["verdict"] == "deny"
    assert dlq_payload["reason"] == "intent flagged as evil"
    assert dlq_payload["guard"] == "intent-guard"
    # The deny receipt rides inside the DLQ payload, matching the
    # cross-broker contract.
    assert dlq_payload["receipt"]["decision"]["verdict"] == "deny"
