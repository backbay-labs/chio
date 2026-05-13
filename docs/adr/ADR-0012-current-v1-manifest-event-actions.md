# ADR-0012: Current V1 Manifest Event-Action Planning

- Status: Accepted
- Decision owner: protocol strategy and manifest maintainers
- Related plan items: PR 652 event action schema, broker mediation, SDK migration

## Context

The current manifest schema cannot name broker publish or consume actions as
first-class permissions. Event systems therefore collapse into generic tool
calls or provider-specific parameters, which weakens replay and policy
explainability. PR 652 research proposed `EventPublish` and `EventConsume`.
Because Chio is unreleased, the planning target is the current v1 manifest
shape, not a new manifest-generation rollout.

## Decision

There is no manifest schema-ceiling field or legacy compatibility path before
release. All Chio-owned runtime, schema, SDK, and docs surfaces expose the
current v1 manifest shape only. A peer that cannot validate the current
manifest semantics must fail closed.

Current v1 manifest planning adds event actions:

- `EventPublish`
- `EventConsume`

The event action shape includes:

- `broker_id`: operator-configured broker handle.
- `broker_kind`: closed enum for supported broker families.
- `destination` or `source`: topic, subject, queue, bus, stream, or channel
  identifier.
- `schema_id`: optional schema registry identifier or manifest-local schema
  name.
- `payload_constraints`: size, content type, schema validation limits, and redaction
  policy.
- `delivery_constraints`: ordering, idempotency key, retry, and deadline limits
  where supported by the broker.

Initial `broker_kind` variants are `Kafka`, `NatsCore`, `NatsJetStream`,
`Pulsar`, `EventBridge`, `GcpPubSub`, `Sns`, `Sqs`, `RedisStreams`, and
`Amqp`. There is no `Other(String)` escape hatch; unknown broker kinds
fail closed until a later ADR extends the enum.

Unknown `RequiredPermissions` fields fail closed. Manifest validation must use
strict unknown-field rejection for permission blocks. A manifest carrying event
permissions before the current v1 event-action implementation lands is rejected.

Enforcement runs in three layers:

1. Manifest admission in `chio-manifest` validates schema version, broker
   identity, and permission vocabulary.
2. Guard/action extraction maps broker activity to typed
   `ToolAction::EventPublish` or `ToolAction::EventConsume`; this is the
   enforcement decision point.
3. SDKs and bridges enforce broker-specific wire constraints before dispatch,
   but they cannot widen manifest scope or turn a generic action into a typed
   mediated event action after the fact.

SDK migration:

- Add new SDK methods or tool names for event publish and consume.
- Keep current generic parameter paths during a migration window, but receipts
  for generic paths must not claim typed event mediation until the action maps to
  the current v1 event shape.
- Migration docs must name current generic behavior, current event-action
  behavior, and rejection behavior.

## Rationale

Removing pre-release manifest schema negotiation keeps the plan focused on one
current v1 shape. Event brokers have security-relevant dimensions that generic
tool calls cannot express well: destination, schema, ordering, replay, and
broker identity. Making those dimensions typed is necessary before broker
adapter tickets can make mediated claims.

Strict unknown-field behavior is required because event permissions are
capability scope. Unknown permission fields cannot be safely ignored.

## Consequences

### Positive

- Broker publish and consume actions become replayable and policy-explainable.
- Current v1 event-action rollout has a clear rejection path.
- SDKs can migrate without making false typed-mediation claims.

### Negative

- Manifest parsing becomes stricter.
- Existing generic event integrations need migration shims.
- Broker-specific constraints still require SDK and bridge work after the ADR.

## Required Follow-up

- Add rejection tests for manifests that include event permissions before the
  current v1 event-action implementation is enabled.
- Add rejection tests for unknown `RequiredPermissions` fields.
- Add typed `ToolAction::EventPublish` and `ToolAction::EventConsume` tests.
- Draft SDK migration notes before broker implementation tickets.
