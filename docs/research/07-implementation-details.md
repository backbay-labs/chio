# Implementation Details

## Objective

This document turns the strategy into plausible implementation steps that fit the current repository.

It is intentionally concrete. The point is to reduce the number of "we should probably support X" statements that do not name where X should live.

## 1. Session and JSON-RPC Layer

## Proposed local work

Add a session abstraction that owns:

- request ID tracking
- cancellation bookkeeping
- progress token bookkeeping
- subscription bookkeeping
- negotiated feature flags

Suggested module split:

```text
crates/arc-kernel/src/session/
  mod.rs
  lifecycle.rs
  inflight.rs
  subscriptions.rs
  progress.rs
  cancellation.rs
```

If that grows too large or needs reuse, promote it into a dedicated crate later.

## Suggested types

```rust
struct Session {
    id: SessionId,
    protocol_version: String,
    peer_capabilities: PeerCapabilities,
    auth_context: SessionAuthContext,
    roots: Vec<Root>,
    inflight: InflightRegistry,
    subscriptions: SubscriptionRegistry,
}
```

```rust
struct InflightRequest {
    request_id: JsonRpcId,
    operation_kind: OperationKind,
    started_at: Instant,
    progress_token: Option<ProgressToken>,
    cancellable: bool,
}
```

## Why start here

Without a session layer:

- progress and cancellation become ad hoc
- nested flows become unmanageable
- JSON-RPC compatibility ends up leaking everywhere

## 2. Normalize requests before enforcement

The kernel should evaluate normalized operations, not raw JSON-RPC payloads.

Suggested flow:

```text
JSON-RPC request
  -> edge validation
  -> normalization into SessionOperation
  -> capability lookup / issuance context
  -> kernel evaluation
  -> provider dispatch
  -> result translation back to JSON-RPC
```

Suggested intermediate type:

```rust
struct OperationContext {
    session_id: SessionId,
    peer: PeerIdentity,
    subject: ActionSubject,
    roots: Vec<Root>,
    request_id: RequestId,
    parent_request_id: Option<RequestId>,
    progress_token: Option<ProgressToken>,
}
```

This becomes the common substrate for tools, resources, prompts, and nested flows.

## 3. Capability model evolution

The current `ArcScope` is centered on tool grants.

That is acceptable for the prototype, but it becomes awkward once resources and prompts arrive.

## Recommended evolution path

### Step 1

Keep `ToolGrant`, but add constraints that are actually enforced:

- path prefix
- domain exact
- domain glob
- regex match
- max length

This already exists structurally in [capability.rs](../../crates/chio-core-types/src/capability.rs), but most of the runtime path does not yet turn it into pervasive enforcement behavior.

### Step 2

Add new grant types:

- `ResourceGrant`
- `PromptGrant`
- `SamplingGrant`
- `ElicitationGrant`

### Step 3

Replace:

```rust
pub struct ArcScope {
    pub grants: Vec<ToolGrant>,
}
```

with something closer to:

```rust
pub struct ArcScope {
    pub grants: Vec<Grant>,
}
```

This is a semver-significant change, so it belongs before `v1`, not after.

## 4. Policy integration

The CLI currently detects HushSpec but does not fully use it as the runtime truth.

That should be fixed early.

## Concrete change

Replace the current split logic with a single loaded policy object:

```rust
enum LoadedPolicy {
    ArcYaml(ArcPolicy),
    HushSpec {
        spec: HushSpec,
        compiled: CompiledPolicy,
    },
}
```

Then update kernel construction to consume `LoadedPolicy` directly.

Benefits:

- no fake fallback policy
- no duplicated logic for default scopes
- the richer policy compiler becomes operational immediately

## Additional near-term policy work

- add fixture policies for tools, resources, prompts, and nested-flow approvals
- compile policy-derived grants as part of session initialization
- embed the canonical compiled-policy hash into receipts, not only the source file hash

## 5. Tools parity details

## Metadata parity

Current `ToolDefinition` in `arc-manifest` is missing some MCP-facing fields that matter for compatibility:

- title
- icons
- annotations
- execution metadata

Recommended change:

- add an MCP-facing compatibility metadata block rather than forcing core types to become UI-heavy

Example:

```rust
struct ToolCompatMetadata {
    title: Option<String>,
    icons: Vec<Icon>,
    annotations: Option<serde_json::Value>,
    output_schema: Option<serde_json::Value>,
    execution: Option<ExecutionMetadata>,
}
```

Then the MCP edge can render full tool definitions without bloating kernel enforcement logic.

## Result parity

Current MCP adapter result conversion handles text and image content.

It should expand to support:

- audio
- resource links
- embedded resources
- structured content

This is especially important if ARC wants to host rich MCP-compatible tools rather than flatten everything into text.

## 6. Resource implementation plan

Resources should not be implemented as fake tools.

## Suggested internal API

```rust
trait ResourceProvider {
    fn provider_id(&self) -> &str;
    fn list(&self, cursor: Option<String>) -> Result<ResourcePage, ProviderError>;
    fn read(&self, uri: &str) -> Result<ResourceContents, ProviderError>;
    fn list_templates(&self) -> Result<Vec<ResourceTemplate>, ProviderError>;
    fn subscribe(&self, uri: &str, session: SessionId) -> Result<(), ProviderError>;
    fn unsubscribe(&self, uri: &str, session: SessionId) -> Result<(), ProviderError>;
}
```

## Enforcement hooks

Before resource reads:

- validate URI against `ResourceGrant`
- enforce roots and path rules if the URI is filesystem-backed
- attach receipt evidence using normalized URI and provider identity

## Notification model

The session layer should own fanout for:

- `notifications/resources/updated`
- `notifications/resources/list_changed`

Resource providers should publish events into the session layer rather than talking to transports directly.

## 7. Prompt implementation plan

Prompts are tricky because they are server-originated but user-controlled.

The mistake to avoid is treating `prompts/get` like a normal model-controlled tool call.

## Suggested internal API

```rust
trait PromptProvider {
    fn list(&self, cursor: Option<String>) -> Result<PromptPage, ProviderError>;
    fn get(&self, name: &str, arguments: serde_json::Value) -> Result<ResolvedPrompt, ProviderError>;
}
```

## Policy idea

Prompt retrieval should support policy gates such as:

- prompt name allowlist
- argument schema and size checks
- optional prompt-injection scanning on prompt bodies and embedded resources

That aligns well with the project's security thesis and with `arc-policy` detection work.

## 8. Sampling and elicitation design

This is the highest-risk area.

## Design constraints

- nested requests must remain attributable
- client remains in control of model credentials
- users must be able to deny high-risk nested requests
- nested flows must generate receipts

## Recommended implementation model

Treat sampling and elicitation as child requests linked to a parent request.

Suggested receipt fields:

- `parent_request_id`
- `session_id`
- `flow_type`
- `approval_state`

Suggested state flow:

```text
Tool or prompt request
  -> server requests sampling/elicitation
  -> edge creates child request object
  -> policy checks nested-flow permission
  -> client review / approval path if required
  -> result returns to server-side flow
  -> final parent receipt includes child request references
```

This preserves evidence and makes auditing of multi-step workflows possible.

## Recommended conservative `v1` behavior

- allow nested flows only when explicitly declared in session capabilities and policy
- default deny tool-enabled sampling unless both client and policy allow it
- require receipts for both the child request and the parent completion

## 9. Streaming, progress, and cancellation

The protocol draft already sketches stream receipts. The implementation should follow the same division:

- edge layer forwards chunks and notifications
- kernel tracks authoritative stream state and final receipt

## Suggested implementation objects

```rust
struct StreamState {
    request_id: RequestId,
    started_at: Instant,
    chunk_count: u64,
    content_hash_state: HashAccumulator,
    total_bytes: u64,
    cancelled: bool,
}
```

```rust
enum OperationOutcome {
    Completed(Value),
    Denied(DenyReason),
    Cancelled { reason: Option<String> },
    Incomplete { reason: String, chunks_received: u64 },
}
```

## Implementation rule

Do not let transport adapters invent terminal states.

The kernel should remain the source of truth for:

- whether work completed
- whether it was cancelled
- whether it was interrupted
- which receipt was signed

## 10. Trust plane implementation

## Capability authority

Initial practical implementation:

- local HTTP service or in-process trait-backed service
- issues signed capabilities
- supports revocation queries
- can later back onto a database

Core interface:

```rust
trait CapabilityAuthority {
    fn issue(&self, request: IssueRequest) -> Result<CapabilityToken, AuthorityError>;
    fn revoke(&self, capability_id: &str) -> Result<(), AuthorityError>;
    fn is_revoked(&self, capability_id: &str) -> Result<bool, AuthorityError>;
}
```

## Receipt store

Start simpler than a transparency log.

Practical first backend:

- SQLite with append-only semantics at the application layer

Schema sketch:

- receipts table
- receipt_events table for streams and nested-flow lineage
- indexes on capability_id, request_id, session_id, timestamp, decision

Later backends:

- object store plus index
- Merkle batching service
- transparency witness service

## 11. Conformance and interop

`v1` needs two suites, not one.

## MCP compatibility suite

Questions:

- does ARC answer the expected JSON-RPC methods?
- does it preserve important tool/resource/prompt metadata?
- does it obey lifecycle, pagination, and notification semantics?

## ARC security suite

Questions:

- are capabilities enforced correctly?
- are denials signed?
- do nested flows preserve lineage?
- do streams produce correct terminal receipts?
- does revocation propagate correctly?

## Suggested fixture categories

- minimal tool server
- rich tool server with output schema and resource links
- resource server with subscriptions
- prompt server with arguments
- nested sampling server
- cancellable long-running task

## 12. CLI and operator experience

The current CLI is too small for the eventual system.

Likely future command groups:

- `arc serve`
- `arc proxy mcp`
- `arc policy`
- `arc receipts`
- `arc capabilities`
- `arc ca`
- `arc doctor`

That should not all ship at once, but the eventual operator story should be reflected in the docs early so the architecture does not stay CLI-hostile.

## 13. Immediate implementation backlog

If work starts now, the first concrete engineering sequence I would use is:

1. introduce `LoadedPolicy` and fully operationalize HushSpec compilation
2. add a session abstraction and in-flight registry
3. add a JSON-RPC edge layer for tool-only parity
4. enrich tool metadata and result compatibility
5. add resources as a first-class provider type
6. add prompts as a first-class provider type
7. design and test nested-flow receipts before implementing full sampling
8. add stream state and cancellation semantics
9. externalize revocation and receipts

That order keeps the project building on its strongest assets instead of dispersing into too many protocol features at once.
