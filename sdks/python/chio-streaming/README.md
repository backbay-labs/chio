# chio-streaming

Chio protocol middleware for every mainstream event bus.

| Broker | Module | Consumer wire | Allow side effect | Deny side effect |
|---|---|---|---|---|
| Kafka | `chio_streaming` (top-level) | `confluent-kafka` | receipt produce + offset commit (transactional, EOS v2) | DLQ produce + offset commit (same transaction) |
| NATS JetStream | `chio_streaming.nats` | `nats-py` | `js.publish(receipt_subject, ...)` + `msg.ack()` | `js.publish(dlq_subject, ...)` + `msg.ack()` (or `term`) |
| Apache Pulsar | `chio_streaming.pulsar` | `pulsar-client` (sync or async) | receipt producer `send` + `consumer.acknowledge` | DLQ producer `send` + `consumer.acknowledge` |
| AWS EventBridge | `chio_streaming.eventbridge` | Lambda target | `events.put_events(receipt_bus, ...)` | `events.put_events(dlq_bus, ...)` |
| Google Cloud Pub/Sub | `chio_streaming.pubsub` | `google-cloud-pubsub` | `publisher.publish(receipt_topic, ...)` + `message.ack()` | `publisher.publish(dlq_topic, ...)` + `message.ack()` (or `nack`) |
| Redis Streams | `chio_streaming.redis_streams` | `redis.asyncio` | `XADD receipt_stream ...` + `XACK` | `XADD dlq_stream ...` + `XACK` (or keep in PEL) |
| Apache Flink | `chio_streaming.flink` | PyFlink DataStream | receipt side output + `KafkaSink EXACTLY_ONCE` (2PC) | DLQ side output + `KafkaSink EXACTLY_ONCE` (2PC) |

Every middleware shares the same evaluation pipeline: call the Chio
sidecar with ``(capability_id, tool_server, tool_name, parameters)``,
and route the outcome to the allow or deny path. The only differences
are the broker's native ack / ordering semantics and what "publish"
means to that broker.

## Install

```bash
# core only (Kafka middleware compiles but confluent-kafka is not installed)
pip install chio-streaming

# pick your brokers
pip install "chio-streaming[kafka]"
pip install "chio-streaming[nats]"
pip install "chio-streaming[pulsar]"
pip install "chio-streaming[eventbridge]"
pip install "chio-streaming[pubsub]"
pip install "chio-streaming[redis]"
pip install "chio-streaming[flink]"

# everything
pip install "chio-streaming[all]"
```

## Shared primitives

All broker modules build on a handful of primitives in
`chio_streaming.core`:

- `ChioClientLike` -- the async sidecar protocol every middleware
  speaks.
- `DLQRouter` -- picks the DLQ topic / subject / stream per source and
  builds the canonical denial envelope. Same class on every broker.
- `ReceiptEnvelope` / `build_envelope` -- canonical JSON receipt
  envelope produced on allow. Same wire format everywhere.
- `Slots` -- lazy asyncio semaphore used by every middleware to cap
  in-flight evaluations and protect the sidecar from bursty topics.

You rarely need these directly; they show up in the middleware
constructors.

## Kafka

Kafka is the only broker with native EOS, so it gets a dedicated
transactional path. Offset commit + receipt publish (allow) or offset
commit + DLQ publish (deny) become visible together or not at all.

```python
import asyncio

from chio_sdk.client import ChioClient
from chio_streaming import (
    ChioConsumerConfig,
    ChioConsumerMiddleware,
    DLQRouter,
)
from confluent_kafka import Consumer, Producer


def build_consumer() -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": "localhost:9092",
            "group.id": "research-agents",
            "enable.auto.commit": False,
            "isolation.level": "read_committed",
        }
    )


def build_producer() -> Producer:
    producer = Producer(
        {
            "bootstrap.servers": "localhost:9092",
            "transactional.id": "research-agents-tx",
            "enable.idempotence": True,
        }
    )
    producer.init_transactions()
    return producer


async def run() -> None:
    consumer = build_consumer()
    producer = build_producer()
    consumer.subscribe(["research-tasks"])

    async with ChioClient("http://127.0.0.1:9090") as chio:
        middleware = ChioConsumerMiddleware(
            consumer=consumer,
            producer=producer,
            chio_client=chio,
            dlq_router=DLQRouter(default_topic="chio-denied-events"),
            config=ChioConsumerConfig(
                capability_id="cap-research-agents",
                tool_server="kafka://prod",
                scope_map={"research-tasks": "events:consume:research-tasks"},
                receipt_topic="chio-receipts",
                transactional=True,
                max_in_flight=32,
                consumer_group_id="research-agents",
            ),
        )

        async def handle(msg, receipt):
            ...

        while True:
            await middleware.poll_and_process(handle)


asyncio.run(run())
```

Transactional semantics (atomic):

- **Allow**: offset commit + receipt publish visible together or not at all.
- **Deny**: offset commit + DLQ publish visible together or not at all.
- **Handler error / broker failure**: both rolled back; Kafka redelivers.

Not atomic:

- External side-effects inside your handler (HTTP, DB writes). Use an
  outbox.
- DLQ on a different cluster. Keep the DLQ co-located.
- Sidecar RPC. If the transaction aborts, the sidecar may still have a
  receipt recorded; the receipt *envelope* only appears on commit.

Set `config.transactional=False` to degrade to best-effort
at-least-once when brokers without EOS are involved.

## NATS JetStream

```python
from chio_streaming.nats import (
    ChioNatsConsumerConfig,
    build_nats_middleware,
)
from chio_streaming.dlq import DLQRouter
import nats

nc = await nats.connect("nats://localhost:4222")
js = nc.jetstream()

mw = build_nats_middleware(
    publisher=js,
    chio_client=chio,
    dlq_router=DLQRouter(default_topic="chio.dlq"),
    config=ChioNatsConsumerConfig(
        capability_id="cap-research",
        tool_server="nats://prod",
        scope_map={"tasks.research": "events:consume:tasks.research"},
        receipt_subject="chio.receipts",
    ),
)

sub = await js.pull_subscribe("tasks.research", durable="research-agent")

async def handler(msg, receipt):
    ...

while True:
    msgs = await sub.fetch(32, timeout=1.0)
    for msg in msgs:
        await mw.dispatch(msg, handler)
```

- `receipt_subject` receives the allow envelope.
- Deny XACKs (or terms, if configured) after the DLQ publish so the
  source stream does not redeliver.
- Handler errors `nak` (or `term`) to trigger JetStream redelivery.

## Apache Pulsar

```python
from chio_streaming.pulsar import (
    ChioPulsarConsumerConfig,
    build_pulsar_middleware,
)
import pulsar

client = pulsar.Client("pulsar://localhost:6650")
consumer = client.subscribe(
    "persistent://public/default/orders",
    subscription_name="order-agents",
)
receipt_producer = client.create_producer(
    "persistent://public/default/chio-receipts"
)
dlq_producer = client.create_producer(
    "persistent://public/default/chio-dlq"
)

mw = build_pulsar_middleware(
    consumer=consumer,
    receipt_producer=receipt_producer,
    dlq_producer=dlq_producer,
    chio_client=chio,
    dlq_topic="persistent://public/default/chio-dlq",
    config=ChioPulsarConsumerConfig(
        capability_id="cap-orders",
        tool_server="pulsar://prod",
        scope_map={
            "persistent://public/default/orders": "events:consume:orders",
        },
        receipt_topic="persistent://public/default/chio-receipts",
    ),
)

async def handler(msg, receipt):
    ...

while True:
    msg = consumer.receive()
    await mw.dispatch(msg, handler)
```

- Works with both the sync `pulsar-client` API and the async wrapper:
  the middleware awaits whichever shape the consumer / producer
  returns.
- Deny publishes to the Chio DLQ topic and acknowledges so Pulsar's
  native DLQ policy is not also triggered.

## AWS EventBridge

```python
import asyncio
import boto3
from chio_streaming.eventbridge import (
    ChioEventBridgeConfig,
    build_eventbridge_handler,
)

events_client = boto3.client("events")

handler = build_eventbridge_handler(
    chio_client=chio,
    events_client=events_client,
    config=ChioEventBridgeConfig(
        capability_id="cap-lambda",
        tool_server="aws:events://prod",
        scope_map={"OrderPlaced": "events:consume:OrderPlaced"},
        receipt_bus="chio-receipt-bus",
        dlq_bus="chio-dlq-bus",
    ),
)


async def process(event, receipt):
    ...


def lambda_handler(event, context):
    outcome = asyncio.run(handler.evaluate(event, handler=process))
    return outcome.lambda_response()
```

- `on_sidecar_error="deny"` fails closed so EventBridge does not retry
  while the sidecar is down (useful for targets behind circuit
  breakers).
- Denials are put on the DLQ bus with the canonical Chio denial
  envelope; the Lambda response carries `{statusCode: 403, reason, guard}`.

## Google Cloud Pub/Sub

```python
import asyncio
from google.cloud import pubsub_v1
from chio_streaming.pubsub import (
    ChioPubSubConfig,
    build_pubsub_middleware,
)

subscriber = pubsub_v1.SubscriberClient()
publisher = pubsub_v1.PublisherClient()

mw = build_pubsub_middleware(
    publisher=publisher,
    chio_client=chio,
    config=ChioPubSubConfig(
        capability_id="cap-agents",
        tool_server="gcp:pubsub://prod",
        subscription="projects/my-project/subscriptions/agent-tasks",
        receipt_topic="projects/my-project/topics/chio-receipts",
        dlq_topic="projects/my-project/topics/chio-dlq",
    ),
)


async def process(msg, receipt):
    ...


def callback(msg):
    asyncio.run(mw.dispatch(msg, handler=process))


future = subscriber.subscribe(
    "projects/my-project/subscriptions/agent-tasks",
    callback=callback,
)
future.result()
```

- Scope resolution order: `X-Chio-Subject` attribute, `subject`
  attribute, subscription name.
- Deny `ack`s by default so the subscription's native dead-letter
  policy is not also triggered. Set `deny_strategy="nack"` to
  delegate to the native DLQ instead.

## Redis Streams

```python
import asyncio
import redis.asyncio as redis
from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    build_redis_streams_middleware,
)

r = redis.Redis.from_url("redis://localhost:6379")

mw = build_redis_streams_middleware(
    client=r,
    chio_client=chio,
    config=ChioRedisStreamsConfig(
        capability_id="cap-agents",
        tool_server="redis://prod",
        group_name="agent-swarm",
        scope_map={"tasks": "events:consume:tasks"},
        receipt_stream="chio-receipts",
        receipt_maxlen=1_000_000,
        dlq_maxlen=1_000_000,
    ),
    dlq_stream="chio-dlq",
)

await r.xgroup_create("tasks", "agent-swarm", id="0", mkstream=True)

async def handler(entry, receipt):
    ...  # entry.stream / entry.entry_id / entry.fields

while True:
    resp = await r.xreadgroup(
        "agent-swarm", "agent-1", {"tasks": ">"}, count=10, block=1000
    )
    for stream, messages in resp:
        stream_name = stream.decode() if isinstance(stream, bytes) else stream
        for entry_id, fields in messages:
            entry_id_str = (
                entry_id.decode() if isinstance(entry_id, bytes) else entry_id
            )
            await mw.dispatch(
                stream=stream_name,
                entry_id=entry_id_str,
                fields=fields,
                handler=handler,
            )
```

- Receipt and DLQ envelopes are written as `XADD` entries with
  canonical JSON in a `payload` field plus the Chio headers surfaced
  as top-level fields for `XRANGE` filtering.
- Deny XACKs by default so the PEL does not grow unboundedly. Set
  `deny_strategy="keep"` if you want to triage denials via
  `XPENDING` / `XAUTOCLAIM` before acknowledging.
- Handler errors leave the entry in the PEL by default; Redis's
  consumer-group redelivery (or `XAUTOCLAIM`) handles retries.

## Apache Flink

Flink owns exactly-once end-to-end via aligned checkpoints and 2PC
sinks, so this integration does not drive transactions itself. It
evaluates each record against a Chio capability and emits canonical
receipt / DLQ envelopes to Flink side outputs. The bytes on the
receipt and DLQ streams are byte-identical to every other
middleware's output (same `build_envelope` / `DLQRouter.build_record`
path), so a single downstream consumer audits all ingress regardless
of source.

Two operator shapes ship. Prefer the async pair:

```python
from pyflink.common import Time
from pyflink.common.typeinfo import Types
from pyflink.datastream import (
    AsyncDataStream,
    OutputTag,
    StreamExecutionEnvironment,
)

from chio_sdk.client import ChioClient
from chio_streaming import DLQRouter
from chio_streaming.flink import (
    DLQ_TAG_NAME,
    RECEIPT_TAG_NAME,
    ChioAsyncEvaluateFunction,
    ChioFlinkConfig,
    ChioVerdictSplitFunction,
    register_dependencies,
)

RECEIPT_TAG = OutputTag(RECEIPT_TAG_NAME, Types.PICKLED_BYTE_ARRAY())
DLQ_TAG = OutputTag(DLQ_TAG_NAME, Types.PICKLED_BYTE_ARRAY())

env = StreamExecutionEnvironment.get_execution_environment()
env.enable_checkpointing(60_000)
register_dependencies(env)

config = ChioFlinkConfig(
    capability_id="cap-fraud",
    tool_server="flink://fraud-job",
    client_factory=lambda: ChioClient("http://127.0.0.1:9090"),
    dlq_router_factory=lambda: DLQRouter(default_topic="chio-fraud-dlq"),
    scope_map={"transactions": "events:consume:transactions"},
    receipt_topic="chio-fraud-receipts",
    max_in_flight=64,
    on_sidecar_error="deny",
    subject_extractor=lambda event: "transactions",
)

evaluated = AsyncDataStream.unordered_wait(
    transactions,
    ChioAsyncEvaluateFunction(config),
    Time.milliseconds(10_000),
    128,
    Types.PICKLED_BYTE_ARRAY(),
)
split = evaluated.process(ChioVerdictSplitFunction())
receipts = split.get_side_output(RECEIPT_TAG)
dlq = split.get_side_output(DLQ_TAG)

split.sink_to(downstream)           # allowed events
receipts.sink_to(kafka_receipt_eos)  # 2PC receipt sink
dlq.sink_to(kafka_dlq_eos)           # 2PC DLQ sink
```

- `ChioAsyncEvaluateFunction` is the primary path. It is an
  `AsyncFunction`, so PyFlink drives the coroutine under
  `AsyncDataStream.unordered_wait(capacity=...)`.
- `ChioVerdictSplitFunction` chains after it to fan out into main /
  receipt / DLQ side outputs. Chained execution means no serialisation
  cost between the two operators.
- `ChioEvaluateFunction` is a single-operator synchronous alternative
  for low-throughput or co-located sidecar deployments.
- `client_factory` and `dlq_router_factory` are required because
  `ChioClient` holds a connection pool that cannot survive cloudpickle
  across the JobManager -> TaskManager boundary.

Wire-compatibility is guaranteed: the bytes on the `chio-receipt`
side output equal `build_envelope(...).value` exactly, and the bytes
on `chio-dlq` equal `DLQRouter.build_record(...).value` exactly.

### Dependency packaging

`register_dependencies(env, requirements_path="./requirements.txt")`
calls `env.set_python_requirements(...)` so workers pip-install
`chio-streaming[flink]` and your Chio SDK at startup. Pass
`python_files=[...]` to additionally ship local packages /
directories via `env.add_python_file(...)`. For air-gapped clusters
or C-extension-hostile images, fall back to
`env.add_python_archive(...)` + `env.set_python_executable(...)`
documented in the PyFlink guide.

### Known limitations

1. **Flink version floor**: `apache-flink >= 2.2.0, < 3.0`. PyFlink's
   `AsyncFunction` surface shipped in 2.2 (FLINK-38560). Users on older
   Flink can fall back to `chio_streaming.middleware` (the Kafka
   middleware) as an interim.
2. **Non-Kafka 2PC sinks**: PyFlink does not ship a
   `TwoPhaseCommitSinkFunction` base class. For non-Kafka receipt
   sinks (HTTP, JDBC, ...) you either write a Java 2PC sink, accept
   at-least-once with `request_id` dedupe, or bridge through an
   intermediate Kafka topic.
3. **AsyncFunction and side outputs**: PyFlink's `AsyncFunction` has
   no `Context` parameter and cannot emit side outputs. The async
   path must chain into `ChioVerdictSplitFunction` to recover the
   receipt / DLQ streams.
4. **Kafka `transaction.timeout.ms`**: must exceed checkpoint
   interval + commit latency. Receipts are lost when transactions
   expire mid-commit.
5. **Sidecar capacity**: total in-flight against the sidecar is
   `capacity * parallelism`. Size the sidecar pool accordingly.

See `examples/flink_fraud_scoring.py` for an end-to-end runnable
example (FileSource -> async evaluate -> split -> FileSink, with a
commented Kafka upgrade path).

## Transactional semantics summary

| Broker | Allow atomicity | Deny atomicity | Handler error |
|---|---|---|---|
| Kafka | offset + receipt transactional | offset + DLQ transactional | abort -> redeliver |
| NATS JetStream | publish then ack | publish then ack / term | nak (or term) |
| Pulsar | send then acknowledge | send then acknowledge | nack (or ack) |
| EventBridge | put_events then return | put_events then return | raise -> Lambda retry |
| Pub/Sub | publish then ack | publish then ack (or nack) | nack (or ack) |
| Redis Streams | XADD then XACK | XADD then XACK (or keep) | leave in PEL (or XACK) |
| Flink | receipt side output + KafkaSink 2PC (EOS) | DLQ side output + KafkaSink 2PC (EOS) | task restart + source rewind |

Everything except Kafka is publish-then-ack: a crash between the
publish and the ack costs a duplicate receipt or DLQ entry, which
downstream consumers should dedupe on `request_id`.

## Testing

Every broker ships a test suite against in-process fakes, so no live
broker is required. See `tests/test_middleware.py`
(Kafka), `tests/test_nats.py`, `tests/test_pulsar.py`,
`tests/test_eventbridge.py`, `tests/test_pubsub.py`, and
`tests/test_redis_streams.py`.

## Integration testing

Live-broker integration tests live under `tests/integration/` and are
gated by the `CHIO_INTEGRATION=1` environment variable so a normal
`uv run pytest` invocation never touches a real broker (the suite is
skipped, not failed, when the gate is off).

The integration stack ships as `deploy/compose/streaming-compose.yml` at the
repo root and currently includes Redis (port `16379`) and NATS with
JetStream enabled (port `14222`). The ports are deliberately offset
from the broker defaults so the stack can coexist with a workspace-wide
Redis on `6379`.

The Makefile target brings the stack up, runs the suite, and tears it
down (even on failure):

```bash
make test-integration
```

To iterate against a long-running stack:

```bash
make infra-up
CHIO_INTEGRATION=1 \
  CHIO_TEST_REDIS_URL=redis://localhost:16379/0 \
  CHIO_TEST_NATS_URL=nats://localhost:14222 \
  uv run pytest tests/integration -v
make infra-down
```

The fixtures in `tests/integration/conftest.py` probe each broker on
startup and emit a clean skip (rather than a connection-error
backtrace) when the broker is unreachable.

### Flink + Kafka path

A second integration stack covers the Flink operators and the Kafka
middleware against real brokers. It ships as
`deploy/compose/streaming-flink-compose.yml` and brings up:

- **Redpanda** (Kafka-API compatible) on port `19092` (host) /
  `9092` (in-cluster).
- **Apache Flink** JobManager + TaskManager on port `18081` (web UI).
  The dockerised Flink is a UI / manual exploration target only --
  the `test_flink_kafka_integration.py` test runs PyFlink in-process
  via `LocalStreamEnvironment` so the Python operator code does not
  need to be shipped into a JobManager container with a matching
  Python version.

Prerequisites:

```bash
# pyflink + confluent-kafka extras
uv sync --extra kafka --extra flink
```

PyFlink (via apache-beam) needs `setuptools<81` (which still ships
`pkg_resources`) plus `--no-build-isolation` for the Beam wheel.
If `uv sync` fails with `ModuleNotFoundError: No module named 'pkg_resources'`,
install Beam manually first:

```bash
uv pip install 'setuptools<81'
uv pip install --no-build-isolation 'apache-beam==2.61.0'
uv pip install 'apache-flink>=2.2.0,<3'
```

JDK 17 is required (Flink 2.2 does not start cleanly on JDK 20+).
Set `JAVA_HOME` accordingly, e.g.:

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
```

The Flink test also needs the `flink-sql-connector-kafka` JAR
(`KafkaSource` is wired into PyFlink's wheel; the Kafka connector
classes are not). The Makefile target stages it under
`sdks/python/chio-streaming/.test-jars/` on first invocation:

```bash
make test-integration-flink   # brings up Redpanda + Flink, runs tests, tears down
```

The umbrella runs both integration suites against their respective
stacks (each leg cleans up before the next):

```bash
make test-integration-all
```

For long-running iteration:

```bash
make infra-flink-up
CHIO_INTEGRATION=1 \
  CHIO_TEST_KAFKA_BOOTSTRAP=localhost:19092 \
  uv run pytest tests/integration/test_kafka_middleware_integration.py tests/integration/test_flink_kafka_integration.py -v
make infra-flink-down
```
