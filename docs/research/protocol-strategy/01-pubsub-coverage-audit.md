# 01 - Pub/Sub and Event-Stream Coverage Audit

> Audited against `/Users/connor/backbay/arc/.claude/worktrees/silly-wu-c32126/`
> as of 2026-05-11. Citations use repo-relative paths.

## TL;DR

The product-owner hypothesis is **partially confirmed and partially wrong, in
both directions**. The kernel itself does not (and should not) sit as a generic
broker subscriber: every Rust bridge in the workspace implements
`ToolServerConnection` (`crates/chio-kernel/src/runtime.rs:255`), which is a
request/response surface, and the only typed egress contract is HTTP-only
(`crates/chio-egress-contract/src/lib.rs:14-39`). There are zero NATS, Kafka,
AMQP, RabbitMQ, EventBridge, GCP Pub/Sub, or WebSub references in any Rust
crate manifest, and only two passing string mentions in code (a Rekor comment
and a Spine/NATS doc-line in `chio-kernel/src/revocation_runtime.rs:9`). But
the hypothesis that publish/consume mediation must therefore be modeled as
"agent's publish call goes through an MCP/HTTP tool" understates what already
ships: the **Python `chio-streaming` SDK** (`sdks/python/chio-streaming/`,
~5000 LOC) is a fully built consumer-side middleware layer for Kafka, NATS
JetStream, Pulsar, EventBridge, GCP Pub/Sub, Redis Streams, and Flink, all of
which call the Chio sidecar at evaluate-tool-call time and route allow/deny
to receipt or DLQ topics with broker-native ack semantics. **AMQP /
RabbitMQ, AWS SNS+SQS, and WebSub have no coverage in any artifact, Rust or
SDK.**

## Per-Broker Coverage

### NATS / JetStream

- **Current coverage:** Python middleware exists end-to-end:
  `sdks/python/chio-streaming/src/chio_streaming/nats.py:1-478`. Wraps a
  `nats.aio.msg.Msg`-shaped consumer
  (`sdks/python/chio-streaming/src/chio_streaming/nats.py:50-66`), calls the
  sidecar via `evaluate_with_chio`
  (`sdks/python/chio-streaming/src/chio_streaming/core.py:71-80`), then either
  `js.publish(receipt_subject)` + `msg.ack()` on allow or
  `js.publish(dlq_subject)` + `msg.ack()`/`msg.term()` on deny. Documented as
  a tier-1 broker in `sdks/python/chio-streaming/README.md:8`. No JetStream
  atomic commit; dedupe is required on `request_id`
  (`sdks/python/chio-streaming/src/chio_streaming/nats.py:1-10`).
- **Gap:** No native Rust implementation. No `ToolServerConnection` bridge
  exposing "publish to NATS" as a tool call - if an MCP server speaks NATS,
  Chio currently sees the MCP RPC, not the broker semantics. No typed
  `NatsEgressContract` analogous to `HttpEgressContract`. No manifest
  primitive for `subject` allowlists. The doc reference in
  `crates/chio-kernel/src/revocation_runtime.rs:9` ("distributed revocation
  feed via Spine/NATS") is aspirational, not implemented.
- **Recommendation:** Keep the Python middleware as the canonical consumer
  story. Add a `NatsSubject` constraint and a `events:consume:{subject}` /
  `events:publish:{subject}` scope shape to `chio-manifest` so policy can name
  subjects. If parity with HTTP egress is wanted, define a
  `NatsEgressContract` (allowed-server-set, allowed-subject-prefix-set) in
  `chio-egress-contract` and have the sidecar enforce it before the SDK
  publishes the receipt envelope.

### Apache Kafka

- **Current coverage:** Best-supported broker. Python middleware in
  `sdks/python/chio-streaming/src/chio_streaming/middleware.py:1-689` wires
  `confluent_kafka.Consumer`/`Producer` (lines 44-80) into a Kafka EOS v2
  transaction that atomically commits offset + receipt produce (allow) or
  offset + DLQ produce (deny). JVM Flink module
  (`sdks/jvm/chio-streaming-flink/README.md`) plus
  `sdks/python/chio-streaming/src/chio_streaming/flink.py` extend this to
  PyFlink DataStreams. Integration tests run against Testcontainers Redpanda
  (`sdks/python/chio-streaming/tests/integration/test_kafka_middleware_integration.py`,
  `sdks/python/chio-streaming/tests/integration/test_flink_kafka_integration.py`).
- **Gap:** Same as NATS - no Rust crate, no `KafkaEgressContract`, no manifest
  primitives for topic/partition scopes. Compacted topics, MirrorMaker
  multi-cluster, and Kafka Streams windowed aggregations are flagged as open
  questions in `docs/protocols/EVENT-STREAMING-INTEGRATION.md:721-742`.
- **Recommendation:** Hardest already done. Promote topic-allowlist /
  consumer-group / partition-bound constraints into `chio-manifest` as
  first-class types so Rust kernels evaluating "publish to topic" tool calls
  routed through MCP/A2A bridges can enforce the same primitives the Python
  middleware enforces today.

### AMQP / RabbitMQ

- **Current coverage:** None. Zero references anywhere - confirmed via
  `grep -rni "amqp\|rabbitmq" --include='*.rs' --include='*.py'
  --include='*.toml' --include='*.md'` (no hits in code; only npm
  `package-lock.json` integrity strings collide). Not listed in the streaming
  SDK table (`sdks/python/chio-streaming/README.md:5-13`). Not in the
  proposed-but-unbuilt list (`docs/protocols/UNIVERSAL-KERNEL-COVERAGE-MAP.md:62`).
- **Gap:** Total. No middleware, no doc plan, no manifest shape, no
  conformance fixture. AMQP's exchange + routing-key model also does not map
  cleanly to the topic/subject pattern the existing primitives assume.
- **Recommendation:** Add a fourth-tier broker module (`chio_streaming.amqp`)
  using `aio-pika` Channel/Queue protocols. Manifest scope shape
  `events:consume:{exchange}:{routing_key}` mirrors RabbitMQ topology. Effort
  is comparable to NATS (broker has manual ack/nack, no native EOS), so
  re-use the JetStream module structure. RabbitMQ Streams (a separate
  product) is closer to Kafka and would route through the EOS-style code
  path.

### AWS EventBridge (and SNS / SQS)

- **Current coverage (EventBridge):** Python Lambda-target handler in
  `sdks/python/chio-streaming/src/chio_streaming/eventbridge.py:1-535`. Wraps
  a `boto3.client("events")` shape
  (`sdks/python/chio-streaming/src/chio_streaming/eventbridge.py:45-49`), uses
  Lambda return value as implicit ack, and routes denials via
  `put_events(DLQ-bus)`. Per-entry 240 KB Detail budget
  (`sdks/python/chio-streaming/src/chio_streaming/eventbridge.py:40-42`).
- **Coverage (SNS / SQS):** None as first-class streaming modules.
  `docs/protocols/AWS-LAMBDA-INTEGRATION.md:234,247` mentions SQS as a
  receipt-flush pipe option, not as a governed agent surface. No
  `chio_streaming.sns` or `chio_streaming.sqs` module.
- **Gap:** EventBridge gap is the same shape as Kafka - manifest still lacks
  detail-type / source / bus-name scope primitives, so Chio policies cannot
  name an EventBridge rule the way an HTTP egress contract names a host. SNS
  topic-ARN scoping and SQS queue-ARN scoping are absent entirely.
- **Recommendation:** Add `chio_streaming.sns` (publish-only) and
  `chio_streaming.sqs` (consume + DLQ to a second queue) modules - both are
  ~200-300 LOC by analogy with the EventBridge file. SNS+SQS together cover
  the "fan-out + buffered consumer" pattern AWS shops actually deploy. Lift
  the `EventBusName` / `DetailType` / `TopicArn` / `QueueArn` strings into
  `chio-manifest` constraint variants so a Rust kernel can verify them when
  the publish call surfaces as a tool call.

### GCP Pub/Sub

- **Current coverage:** Python middleware in
  `sdks/python/chio-streaming/src/chio_streaming/pubsub.py:1-507`. Wraps a
  `google-cloud-pubsub` SubscriberClient, calls the sidecar, then
  `publisher.publish(receipt_topic)` + `message.ack()` (allow) or DLQ topic +
  ack/nack (deny). Listed at
  `sdks/python/chio-streaming/README.md:11`. Test in
  `sdks/python/chio-streaming/tests/test_pubsub.py`.
- **Gap:** No Rust crate. No manifest primitives for `projects/x/topics/y`
  ARNs. Pub/Sub ordering keys and exactly-once delivery (GA in 2023) are not
  yet special-cased; the middleware treats Pub/Sub as at-least-once like
  NATS.
- **Recommendation:** Add a Pub/Sub-specific `EnableExactlyOnceDelivery`
  config flag, and bring `topic`/`subscription` resource names into
  `chio-manifest`. No fundamentally new protocol work needed.

### WebSub (W3C PubSubHubbub)

- **Current coverage:** None. Zero hits in repo across `*.rs`, `*.py`,
  `*.toml`, `*.md` (`grep -rni websub`). Not in
  `docs/protocols/UNIVERSAL-KERNEL-COVERAGE-MAP.md`. Not in
  `docs/protocols/EVENT-STREAMING-INTEGRATION.md`. Not in the streaming SDK
  README table.
- **Gap:** Total, and arguably structural: WebSub is HTTP webhook callbacks,
  which means coverage can ride on the existing `HttpEgressContract`
  (`crates/chio-egress-contract/src/lib.rs:14-39`) for the hub-callback POST,
  but the subscription verification handshake (GET with `hub.challenge`) and
  inbound notification ingest are not modeled. Inbound webhook ingestion is
  a wider gap than WebSub alone - it is how any third-party event service
  (Stripe, GitHub, Slack Events API, WebSub hubs) talks back to an agent.
- **Recommendation:** Lowest priority of the brokers - WebSub itself sees
  little new agent traffic in 2026. Bigger value is a generic "governed
  inbound webhook" surface that uses `HttpEgressContract`-mirrored verifier
  logic to bind a tenant + capability to a callback URL. WebSub falls out as
  one application of that surface.

## External Context (2026 agent-platform stance, one paragraph)

As of 2026, major agent platforms still do not provide first-class
"agent-publishes-to-bus" abstractions: LangChain documents Kafka and
EventBridge only through user-written tools backed by `confluent-kafka` or
`boto3` (https://python.langchain.com/docs/integrations/tools/); the OpenAI
Agents SDK exposes brokers only as user-defined function tools
(https://github.com/openai/openai-agents-python); Anthropic's Claude tool use
guidance and the MCP spec (https://modelcontextprotocol.io/specification)
likewise leave broker semantics to per-server adapters. The emerging pattern
is "broker is a tool server, not a transport for tool calls," which validates
the Chio architecture: the kernel mediates tool calls, and the SDK middleware
mediates broker consume loops. No agent platform we found mediates a broker
at the protocol level.

## Conclusion: What to Build, Prioritized

1. **Promote pub/sub scope primitives into `chio-manifest` and `chio-guards`
   `ToolAction`.** Today `ToolAction`
   (`crates/chio-guards/src/action.rs:16-46`) has no `EventPublish` /
   `EventConsume` variants; the closest is `ExternalApiCall`. Adding these
   plus topic/subject/ARN allowlist constraints is the smallest change that
   lets Rust-side kernels enforce what the Python middleware already
   enforces. Without this, the SDK and kernel describe the same call in
   different vocabularies. (Effort: small, ~1 sprint.)
2. **Fill the AMQP, SNS, and SQS gaps in `chio-streaming`.** Each is a copy of
   an existing module (NATS for AMQP, EventBridge for SNS, NATS for SQS),
   ~300 LOC + integration test. Closes the "we cover the brokers enterprises
   actually run" claim. (Effort: small-medium, one engineer-month.)
3. **Define non-HTTP egress contracts.**
   `crates/chio-egress-contract/src/lib.rs:14` is HTTP-only. Add
   `BrokerEgressContract` (or sibling types per broker family) so kernels
   embedded in publishers can fail-closed on broker target before SDK code
   runs. This is the prerequisite for trustworthy "agent publishes
   `payment.charged`" governance. (Effort: medium.)
4. **Generic inbound-webhook surface (covers WebSub).** A receiver-side
   counterpart to `HttpEgressContract` that binds tenant + capability to a
   callback URL and verifies signatures. WebSub, Stripe webhooks, and SaaS
   event APIs all fall out. (Effort: medium, distinct from broker work.)
5. **Native Rust mirror of `chio-streaming`.** Lowest priority. The Python
   SDK is the practical surface; a Rust port is only worth doing once
   kernels start being embedded inside Rust-native consumers (Materialize,
   Redpanda Function, Vector). Until then, keep parity at the manifest /
   contract layer instead. (Effort: large, defer.)
