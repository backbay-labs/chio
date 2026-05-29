# 09 - Event Action Schema for ToolAction and chio-manifest

> **Historical research note (PR 652):** Use [00-overview-v2.md](00-overview-v2.md) and [18-decision-packet.md](18-decision-packet.md) for planning. This file remains research input, not an implementation ticket. Mentions of later manifest or receipt generations, schema compatibility limits, negotiation, or pre-release compatibility paths are historical sketches. The accepted current plan folds Chio-owned pre-release schema work into v1 only.
>
> Phase A, item R3 from `00-overview.md`. Builds on `01-pubsub-coverage-audit.md`.
> Code paths are cited repo-relative.

## TL;DR

- The Rust kernel cannot today name "publish to Kafka topic X" or "consume NATS subject Y" in its `ToolAction` enum (`crates/chio-guards/src/action.rs:16-46`), so any policy that the Python `chio-streaming` SDK enforces is unverifiable on replay - the kernel sees a generic `ExternalApiCall` or `McpTool` at best. The minimum viable fix is two new variants (`EventPublish`, `EventConsume`) plus a unified `EventDestination` / `EventSource` shape that absorbs Kafka, NATS, Pulsar, EventBridge, Pub/Sub, SNS, SQS, and Redis Streams under a single schema with optional broker-specific fields.
- Adoption is now planned as current `chio.manifest.v1` work because Chio is unreleased. PR 652 review corrected an overclaim here: current negotiation covers capability compatibility limits, not manifest compatibility limits, and the v1-only posture removes manifest version negotiation before release.
- Receipt body extension work is folded into current v1 receipt-kind semantics. The path forward is unified event shape + current v1 manifest planning + current v1 receipt semantics. The Python SDK can upgrade because the current `parameters` dict carries the same logical fields just untyped.

## Current state of `ToolAction`

`ToolAction` (`crates/chio-guards/src/action.rs:16-46`) is a 12-variant enum with no extension trait, no trait bounds beyond `Clone + Debug`, and no provision for adding broker-shaped actions. The closest existing variants are:

- `ExternalApiCall { service: String, endpoint: String }` (line 39) - what `chio-streaming` calls fall through to today via `slack_`, `stripe_`, etc. prefixes (line 369-395). Brokers do not match any prefix.
- `MemoryWrite { store: String, key: String }` (line 41) and `MemoryRead` (line 43) - structurally similar (named target + key) but semantically for vector DBs only.
- `McpTool(String, Value)` (line 26) - the fallback. The whole tool call survives as an opaque `serde_json::Value`. This is what every broker publish currently degrades to when surfaced through an MCP server.

`extract_action()` (line 65-358) is a heuristic dispatcher keyed on `tool_name`. It has no extension point - to add a new variant we patch the dispatcher in-tree. That is fine for this proposal because the Python SDK already controls the surface name; the kernel just needs to recognise it.

## Current state of manifest constraints

`crates/chio-manifest/src/lib.rs` (368 lines, single file) defines:

- `ToolManifest` (line 25) with `schema: String` pinned to `chio.manifest.v1` (line 20). `validate_manifest()` rejects any other value with `UnsupportedSchema` (line 237-239).
- `ToolDefinition` (line 115) carries `input_schema: serde_json::Value` (line 123) - free-form JSON Schema. There is no typed constraint vocabulary like "HTTP host allowlist" or "filesystem path prefix" inside the manifest; those live in guards and `chio-egress-contract`.
- `RequiredPermissions` (line 165) has `read_paths`, `write_paths`, `network_hosts`, `environment_variables`. **There is no `event_subjects` or `broker_targets` field.** This is the most direct gap. Compare with `HttpEgressContract` (`crates/chio-egress-contract/src/lib.rs:14-39`) which has `tenant_egress_namespace`, `allowed_schemes`, `allowed_authority_set` - typed and constrained. Brokers have no analogue.
- The pattern for adding constraints is therefore split across two crates: a typed contract in a sibling crate (egress-contract style), referenced indirectly from manifest input/output schemas. The goal is to bring broker constraints up to the same first-class level by adding them under `RequiredPermissions` plus a new sibling crate `chio-broker-contract` (parallel to `chio-egress-contract`).

Schema posture: `spec/PROTOCOL.md:305-329` describes capability compatibility negotiation, but PR 652 now treats Chio-owned pre-release manifest work as current v1 evolution. Manifest compatibility negotiation is not implemented today and should not be added before release. A peer that cannot validate the current v1 manifest shape fails closed instead of accepting event-publish permissions it cannot enforce.

## EventPublish variant design

```rust
ToolAction::EventPublish {
    broker_id: String,             // opaque identifier of configured broker
    destination: EventDestination,
    payload: EventPayloadDescriptor,
    headers: EventHeaders,
    delivery: DeliveryConstraints,
}
```

Field rationale:

- `broker_id` is the operator-configured handle (e.g. `"kafka-prod-east"`, `"nats-internal-jetstream"`). Identical to the way an HTTP target uses `tenant_egress_namespace`. Receipts include only its SHA-256 to avoid leaking infra topology.
- `destination` is the unified target:

```rust
pub struct EventDestination {
    pub broker_kind: BrokerKind,
    pub name: String,              // topic | subject | bus | ARN | stream key
    pub sub_qualifier: Option<String>, // EventBridge detail-type, Pulsar namespace, etc.
    pub partition_key: Option<String>, // Kafka key, Pub/Sub ordering key, SQS group
}

pub enum BrokerKind {
    Kafka, NatsCore, NatsJetStream, EventBridge, GcpPubSub,
    Sns, Sqs, RedisStreams, Pulsar, Amqp,
}
```

`name` carries the primary broker resource identifier. The cross-broker mapping below covers what goes there. `sub_qualifier` exists because EventBridge always pairs a bus with a detail-type and Pulsar always pairs a namespace with a topic - one field is insufficient. `partition_key` is the optional ordering/routing key that several brokers expose; it is preserved here so policy can constrain it (e.g. "publishing to topic `orders` requires `partition_key` matching tenant id").

- `payload` is `EventPayloadDescriptor` and **does not contain the payload**. It carries hashes and shape metadata, matching how the Kafka middleware already passes only `body_length` and `body_hash` to the sidecar (`sdks/python/chio-streaming/src/chio_streaming/middleware.py:596-605`):

```rust
pub struct EventPayloadDescriptor {
    pub body_hash: String,         // sha256 hex of body bytes
    pub body_length: u64,
    pub content_type: Option<String>,
    pub schema_id: Option<String>, // Confluent SR id, Pulsar schema, etc.
}
```

Reusing existing payload-shape constraints: `chio-data-guards` already owns `QueryResultGuard` (`crates/chio-data-guards/src/result_guard.rs:121`) and `VectorDbGuard` (`vector_guard.rs:318`) for shape and content rules. The broker layer **delegates** to a new `chio-data-guards::EventPayloadGuard` (sibling) that takes `EventPayloadDescriptor` and applies max-size, allowed-content-types, and required-schema-id checks. Do not duplicate the data-shape vocabulary.

- `headers` is `EventHeaders { entries: BTreeMap<String, String> }` plus `BrokerEgressContract`-side allow/deny rules. Headers are the de facto attribute-propagation channel for every broker (Kafka record headers, NATS headers, Pub/Sub attributes, EventBridge has no native headers but the SDK projects them into the detail). Constraints live in the new `chio-broker-contract` crate as `BrokerHeadersPolicy { required: BTreeSet<String>, forbidden: BTreeSet<String>, value_regex: BTreeMap<String, String> }`.

- `delivery` captures QoS:

```rust
pub struct DeliveryConstraints {
    pub class: DeliveryClass,
    pub require_idempotency_key: bool,
    pub max_in_flight: Option<u32>,
}
pub enum DeliveryClass { AtMostOnce, AtLeastOnce, ExactlyOnce }
```

`ExactlyOnce` maps onto Kafka EOS v2 transactions and Pub/Sub exactly-once delivery; `AtLeastOnce` is the default for NATS JetStream, EventBridge, SNS, SQS, Redis Streams; `AtMostOnce` is core NATS. Policy can require a minimum class (e.g. "payments topic requires `ExactlyOnce`").

## EventConsume variant design

Symmetric to publish, but with source semantics:

```rust
ToolAction::EventConsume {
    broker_id: String,
    source: EventSource,
    subscription: SubscriptionConstraints,
    payload: EventPayloadDescriptor,
    headers: EventHeaders,
    delivery: DeliveryConstraints,
}

pub struct EventSource {
    pub broker_kind: BrokerKind,
    pub name: String,              // topic | subject | rule arn | subscription
    pub sub_qualifier: Option<String>, // namespace, etc.
}

pub struct SubscriptionConstraints {
    pub consumer_group: Option<String>,   // Kafka group / SQS group id / Pulsar subscription
    pub durable_name: Option<String>,     // JetStream durable / Pulsar durable subscription
    pub filter_expression: Option<String>,// EventBridge rule pattern, NATS subject filter, Pub/Sub filter
    pub ack_mode: AckMode,
}
pub enum AckMode { Auto, Manual, Transactional }
```

`filter_expression` is broker-native syntax (EventBridge event-pattern JSON, NATS wildcard subjects, Pub/Sub `attributes.type = "x"`). It is opaque to the kernel but recorded in receipts so reviewers can re-evaluate the deny set.

Receive-side `EventPayloadDescriptor` documents what was received (post-fetch) so a deny is auditable. This is the shape the SDK already collects (`middleware.py:596-605`).

## Cross-broker mapping table

| Broker | `name` | `sub_qualifier` | `partition_key` | Header concept | Default QoS |
|---|---|---|---|---|---|
| Kafka | topic | (unused) | message key | record headers | at-least-once (EOS opt-in) |
| NATS core | subject | (unused) | (none) | NATS headers | at-most-once |
| NATS JetStream | subject | stream name | (none) | NATS headers | at-least-once |
| EventBridge | bus name | detail-type | (none) | (synth into detail) | at-least-once |
| GCP Pub/Sub | topic | (unused) | ordering key | attributes | at-least-once (EOS opt-in) |
| SNS | topic ARN | (unused) | (none) | message attributes | at-least-once |
| SQS | queue ARN | (unused) | message group id | message attributes | at-least-once |
| Redis Streams | stream key | (unused) | (none) | entry fields | best-effort |
| Pulsar | topic | namespace | message key | properties | configurable |
| AMQP / RabbitMQ | exchange | routing-key | (none) | properties | at-least-once |

**Decision: one unified schema with optional fields, not per-broker variants.** Three reasons:

1. The Python SDK already converges all brokers onto a single `parameters` dict (`core.py:78`). Per-broker variants would diverge from the existing wire shape.
2. Policy authors want to write "deny publish to any broker if topic starts with `pii.`" across brokers. With per-broker variants that becomes 9 separate policy clauses; with unified `EventDestination.name` it is one.
3. New brokers (Iceberg streams, RisingWave, Materialize) can be added by extending `BrokerKind` only, without a new `ToolAction` variant. The `BrokerKind` enum lives in `chio-core-types` to avoid forcing every guard to update on a new broker.

The cost is that policy authors must consult the table to know which field carries the topic concept on which broker. Mitigation: provide a `EventDestination::topic_concept()` helper that returns the primary identifier regardless of which field it lives in.

## Receipt embedding

The receipt body (`crates/chio-core-types/src/receipt.rs:158-181`) currently holds `action: ToolCallAction` where `ToolCallAction` is `{ parameters: Value, parameter_hash: String }` (line 1148-1153). Event-action receipts need richer fields than an opaque parameter blob.

**Current v1 plan:** embed an `event_decision` block under
`ChioReceiptBody.metadata: Option<Value>` (line 172) until the typed current v1
field lands. The block is:

```json
{
  "event_decision": {
    "kind": "publish" | "consume",
    "broker_id_hash": "sha256:...",
    "broker_kind": "kafka",
    "destination_or_source": {
      "name": "orders",
      "sub_qualifier": null,
      "partition_key_hash": "sha256:...",
    },
    "payload_hash": "sha256:...",
    "payload_length": 4096,
    "delivery_class": "at_least_once",
    "subscription": { "consumer_group_hash": "sha256:..." }  // consume only
  }
}
```

Hashing `broker_id`, `partition_key`, and `consumer_group` keeps receipts portable across customers without leaking infra names; reviewers verify by recomputing.

**Current v1 coordination with X1:** promote `event_decision` to a typed sibling
of `action` in `ChioReceiptBody` only as part of the current v1 receipt-kind
shape. PR 652 review corrected the schema wording: current receipts do not have
a `receipt_schema: SemVer` field, and ADR-0010 rejects schema limit
negotiation before release. The minimum coordination point with X1 is: reserve
`event_decision` as a current v1 field name so X1 does not collide on it.

Pre-release compatibility: dev artifacts may be regenerated or destructively
migrated. Verifiers that cannot validate the current v1 event-decision shape
fail closed.

## Manifest schema version

Historical note: this document originally proposed a `chio.manifest.v2` bump.
The accepted pre-release posture keeps Chio-owned manifest work in current v1.
Event-action fields are rejected until an accepted v1 implementation and tests
land. The proposed added surface was:

```rust
pub struct RequiredPermissions {
    pub read_paths: Option<Vec<String>>,
    pub write_paths: Option<Vec<String>>,
    pub network_hosts: Option<Vec<String>>,
    pub environment_variables: Option<Vec<String>>,
    // v2 additions:
    pub event_publish: Option<Vec<EventEndpointConstraint>>,
    pub event_consume: Option<Vec<EventEndpointConstraint>>,
}

pub struct EventEndpointConstraint {
    pub broker_id: String,
    pub broker_kind: BrokerKind,
    pub name_pattern: String,        // glob: "orders.*", "arn:aws:sns:us-east-1:*:notify-*"
    pub min_delivery_class: Option<DeliveryClass>,
    pub headers_policy: Option<BrokerHeadersPolicy>,
    pub payload_max_bytes: Option<u64>,
}
```

`deny_unknown_fields` on `ToolManifest` (line 24) plus exact schema validation gives the desired fail-closed default. Because Chio is unreleased, event-action permissions should be folded into the current v1 manifest shape rather than creating compatibility plumbing. A kernel that cannot validate those permissions **must not** silently accept event-publish permissions it cannot enforce.

## Python SDK integration

Today `evaluate_with_chio()` (`sdks/python/chio-streaming/src/chio_streaming/core.py:71-111`) calls the sidecar with `tool_name=<per-broker>` and `parameters={topic, partition, offset, key, headers, body_length, body_hash}` (constructed in `middleware.py:577-605`). The kernel classifies that call as `ToolAction::McpTool` today because no prefix matches.

Upgrade path:

1. SDK adds `evaluate_event_action(kind, destination, ...)` returning `ChioReceipt`. Old `evaluate_tool_call` stays for backward compat.
2. `extract_action` (line 65) gains a recognizer for `chio.event.publish.<broker>` / `chio.event.consume.<broker>` that builds the typed variants from parameters.
3. SDK modules switch `tool_name` to `chio.event.<kind>.<broker>` and pass typed fields under `parameters`.
4. Customers on unpatched SDKs keep working: tool names fall through to `McpTool` and existing guards apply.

SDK module layout (`core.py`, `middleware.py` for Kafka, `nats.py`, `pubsub.py`, `pulsar.py`, `eventbridge.py`, `redis_streams.py`, `flink.py`) shows the conversion is mechanical: each module has a `_parameters_for(message, ...)` helper (`middleware.py:577`) that grows the typed fields. Open question for the SDK owner: bump Python `chio-streaming` to 0.2.0 with a deprecation warning on `tool_name=raw-broker-name` for 1-2 releases?

## Migration plan

1. **Land current v1 manifest event permissions.** New
   `EventEndpointConstraint` fields are `Option<Vec<_>>`, defaulting to none.
   Customers can opt in per tool server.

2. **Land `ToolAction::EventPublish` / `EventConsume` plus the `chio.event.*` recognizer.** This is the kernel-side change request: 1 patch to `chio-guards/src/action.rs`, 1 new crate `chio-broker-contract` mirroring `chio-egress-contract`. No existing tool call shape regresses because the recognizer matches only on the `chio.event.` prefix.

3. **Ship Python SDK 0.2.0.** Modules emit `tool_name=chio.event.publish.kafka` and the new typed `parameters`. Customers running 0.1.x continue to get `McpTool` classification with existing rules.

4. **Add `event_decision` metadata to receipts emitted under event actions.**
   Verifiers that do not know about the block fail closed until the typed
   current v1 field lands.

5. **Manifest event-action fixtures and conformance tests.**
   `crates/chio-conformance/` adds rejection coverage for manifests that carry
   event permissions before the current v1 event-action implementation is
   enabled.

6. **Documentation update.** `spec/PROTOCOL.md` adds an "Event actions" subsection cross-referencing `BrokerKind`, mapping table, and fail-closed validation behavior.

Total scope is one engineer-sprint for the Rust side and one for the SDK shift. The hardest part is the SDK rename because it touches seven broker modules and their tests; the kernel side is contained.

## Three-line summary

- **Schema shape:** single unified `EventDestination` / `EventSource` with `BrokerKind` enum + optional fields, not per-broker variants. Cheaper to add brokers, lets policy authors write one rule across brokers, matches the existing Python SDK convergence.
- **Manifest update required:** fold event-action permissions into current `chio.manifest.v1`, additive before release, fail-closed on unknown fields.
- **Output file:** this file.
