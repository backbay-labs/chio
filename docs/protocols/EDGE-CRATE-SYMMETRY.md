# Edge Crate Symmetry: `chio-a2a-edge` and `chio-acp-edge`

Design spec for bidirectional protocol bridging. Edge crates bridge
_outward_: exposing Chio-native tools through a foreign protocol so non-Chio
clients can discover and invoke them. `chio-mcp-edge` is the reference
implementation. This document covers A2A and ACP-Client equivalents.

## 1. The Composability Gap

| Crate | Direction | Protocol |
|-------|-----------|----------|
| `chio-mcp-edge` | outward | MCP |
| `chio-mcp-adapter` | inward | MCP |
| `chio-a2a-adapter` | inward | A2A |
| `chio-acp-proxy` | inward | ACP-Client |

The outward column has only MCP. That means:

- An Chio tool cannot appear in an A2A Agent Card. Agents that speak only
  A2A have no discovery or invocation path.
- An Chio tool cannot appear in an ACP-Client session. Editors like Zed or
  JetBrains that speak ACP-Client cannot use it.
- Cross-protocol discovery is impossible. A tool registered once should be
  listable via MCP `tools/list`, the A2A Agent Card `skills` array, and
  ACP-Client command enumeration from the same kernel.

This is not just a product-completeness issue. It is also a runtime-security
coverage issue: if Chio only exposes or governs MCP-native surfaces cleanly,
security teams may overestimate how much of the agent runtime is actually under
deterministic control.

### Target Scenarios

- **A2A skills.** `chio-a2a-edge` on HTTPS; remote agents discover via
  Agent Card, invoke with `SendMessage`, kernel runs guards and signs
  receipts.
- **ACP-Client capabilities.** Editor connects to `chio-acp-edge` over stdio;
  each authoritative `tool/invoke` triggers a kernel tool invocation with full
  capability validation.
- **One tool, three surfaces.** Single `ToolManifest` loaded once, three
  edge crates translate it. Kernel is the single enforcement point.

### Coverage Principle

`chio-mcp-edge` is the immediate adoption wedge because MCP is the easiest
wrapped surface to deploy today. But edge symmetry matters because wrapped MCP
traffic is only one slice of real agent execution. Chio should avoid implying
that an MCP-facing chokepoint equals complete runtime security.

## 2. `chio-a2a-edge` Design

### 2.1 Core Types

```rust
pub struct A2aEdgeConfig {
    pub agent_name: String,
    pub agent_description: String,
    pub agent_version: String,
    pub base_url: String,
    pub security_schemes: Vec<A2aSecuritySchemeConfig>,
}

pub enum A2aSecuritySchemeConfig {
    BearerToken,
    OAuth2 { token_url: String, scopes: Vec<String> },
    ApiKey { header_name: String },
}

pub struct A2aExposedSkill {
    pub id: String,          // matches Chio tool name
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub tags: Vec<String>,   // "side-effects", "latency:fast", etc.
}

pub struct ChioA2aEdge {
    config: A2aEdgeConfig,
    kernel: ChioKernel,
    agent_id: String,
    capabilities: Vec<CapabilityToken>,
    skills: Vec<A2aExposedSkillBinding>,
    skill_index: BTreeMap<String, usize>,
    task_counter: u64,
    tasks: BTreeMap<String, A2aEdgeTask>,
}
```

### 2.2 Tool Definition Translation

`manifest_tool_to_a2a_skill` maps `ToolDefinition` fields directly.
`has_side_effects` and `latency_hint` become skill tags. The function
mirrors `manifest_tool_to_mcp_tool` in `chio-mcp-edge`.

### 2.3 Agent Card Generation

`ChioA2aEdge::agent_card() -> serde_json::Value` builds the A2A Agent Card
from config and registered skills. Served at
`/.well-known/agent-card.json`. Includes `securitySchemes`,
`securityRequirements`, and a JSONRPC interface entry pointing to
`{base_url}/a2a`.

### 2.4 Request Handling

| A2A Method | Edge Behavior |
|------------|---------------|
| `SendMessage` | Extract `targetSkillId`, resolve binding, submit to the authoritative Chio path, return blocking A2A task/result payload |
| `SendStreamingMessage` | Create a deferred authoritative task with `receiptPending = true` |
| `GetTask` | Resolve a deferred task through the authoritative Chio path and return the terminal receipt-bearing task result |
| `CancelTask` | Cancel a deferred task before execution |

The shipped authoritative A2A profile is now dual-surface: blocking
`SendMessage` for immediate calls and deferred-task `SendStreamingMessage`
plus `GetTask` / `CancelTask` for truthful lifecycle mediation without
pretending push updates exist. Compatibility passthrough helpers remain
explicitly non-authoritative and are compiled only when the crate's
`compatibility-surface` feature is enabled.

### 2.5 Authentication

Inbound credentials are validated before creating a `SessionAuthContext`
(bearer, API key, or OAuth2). The auth context flows into the kernel and
is available to guards for policy decisions.

## 3. `chio-acp-edge` Design

### 3.1 Core Types

```rust
pub struct AcpEdgeConfig {
    pub agent_name: String,
    pub agent_version: String,
    pub advertised_capabilities: AcpAdvertisedCapabilities,
}

pub struct AcpAdvertisedCapabilities {
    pub streaming: bool,
    pub permissions: bool,
}

pub struct AcpExposedCommand {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    pub has_side_effects: bool,
}

pub struct ChioAcpEdge {
    config: AcpEdgeConfig,
    kernel: ChioKernel,
    agent_id: String,
    capabilities: Vec<CapabilityToken>,
    commands: Vec<AcpExposedCommandBinding>,
    command_index: BTreeMap<String, usize>,
    session_counter: u64,
    sessions: BTreeMap<String, AcpEdgeSession>,
}
```

`AcpExposedCommandBinding` pairs an `AcpExposedCommand` with `server_id`
and `tool_name`. `AcpEdgeSession` tracks the ACP-Client session ID, kernel
session ID, and auth context.

### 3.2 Tool Definition Translation

`manifest_tool_to_acp_command` maps name, description, `input_schema`
(as `parameters_schema`), and `has_side_effects` directly.

### 3.3 ACP-Client Protocol Handling

| ACP-Client Method | Edge Behavior |
|------------|---------------|
| `session/list_capabilities` | Return the truthful authoritative ACP-Client capability surface |
| `session/request_permission` | Capability-aware preview only; does not imply receipt-bearing execution by itself |
| `tool/invoke` | Blocking authoritative invocation path with Chio receipt metadata |
| `tool/stream` | Create a deferred authoritative task with receipt-pending metadata |
| `tool/cancel` | Cancel a deferred task before execution |
| `tool/resume` | Resolve a deferred task through the authoritative Chio path and return the terminal result |

```rust
The shipped authoritative ACP-Client profile is now blocking `tool/invoke` plus a
capability-aware preview surface and a deferred-task lifecycle via
`tool/stream`, `tool/cancel`, and `tool/resume`. Compatibility passthrough
helpers remain explicitly non-authoritative and are compiled only when the
crate's `compatibility-surface` feature is enabled.
```

### 3.4 Session Update Notifications

The shipped authoritative ACP-Client profile does not emit receipt-bearing
`session/update` notifications. That richer lifecycle remains future work and
must not be implied by the current edge surface.

### 3.5 Permission Gating

`session/request_permission` replaces `chio-acp-proxy`'s allowlist model
with the kernel's full capability pipeline (guards + budgets). The edge
maps the ACP-Client permission type to a Chio `Operation` and scope, then
delegates to `kernel.check_capability(...)`.

### 3.6 Transport

Primary transport is stdio, matching how editors launch ACP-Client agents:

```rust
impl ChioAcpEdge {
    pub fn serve_stdio<R: BufRead, W: Write>(
        &mut self, reader: R, writer: W,
    ) -> Result<(), AcpEdgeError> { /* ... */ }
}
```

## 4. Shared Edge Abstractions

All three edge crates follow the same structural pattern:

1. Accept `Vec<ToolManifest>` at construction.
2. Translate each `ToolDefinition` into protocol-native format.
3. Build `BTreeMap<String, usize>` index for O(1) name lookup.
4. On request: resolve binding, build `OperationContext` +
   `ToolCallOperation`, submit to kernel.
5. Translate `SessionOperationResponse` into protocol response shape.

### 4.1 No Shared `ProtocolEdge` Trait

The protocols have fundamentally different lifecycles (MCP: stateful
handshake; A2A: stateless HTTP with task-based async; ACP-Client: session-scoped
JSON-RPC). A shared trait would be too abstract to be useful. The pattern
is documented here; each crate implements it directly.

### 4.2 Shared Utilities (`chio-edge-common`)

Candidates for a small internal crate:

```rust
pub fn latency_hint_label(hint: LatencyHint) -> &'static str;

pub fn build_operation_context(
    request_id: RequestId, agent_id: &str,
    progress_token: Option<ProgressToken>,
) -> OperationContext;

pub fn tool_output_to_content_blocks(output: &ToolCallOutput) -> Vec<Value>;

pub fn iso8601_now() -> String;
```

### 4.3 Common Config Shape

| Field | MCP | A2A | ACP-Client |
|-------|-----|-----|-----|
| Name | `server_name` | `agent_name` | `agent_name` |
| Version | `server_version` | `agent_version` | `agent_version` |
| Kernel | `ChioKernel` | `ChioKernel` | `ChioKernel` |
| Caps | `Vec<CapabilityToken>` | `Vec<CapabilityToken>` | `Vec<CapabilityToken>` |
| Manifests | `Vec<ToolManifest>` | `Vec<ToolManifest>` | `Vec<ToolManifest>` |

### 4.4 Semantic Publication Gates

Edge symmetry does **not** mean every tool should automatically appear on every
protocol surface. Before publication, each edge should classify the fidelity of
the projection:

```rust
pub enum EdgePublicationFidelity {
    Lossless,
    Adapted { caveats: Vec<String> },
    Unsupported { reason: String },
}
```

Examples:

- A simple JSON request/response tool may be `Lossless` on MCP, A2A, and ACP-Client.
- A long-running task with partial artifacts may be `Lossless` on MCP/A2A but
  only `Adapted` on ACP-Client if the editor surface cannot represent the lifecycle
  cleanly.
- A tool that depends on interactive ACP-Client permission prompts may be
  `Unsupported` on A2A if no honest translation exists.

The registry and discovery surfaces should publish caveats alongside any
`Adapted` tool rather than implying protocol equivalence where it does not
exist.

The current edge implementations now enforce this as runtime policy rather than
just design guidance:

- Shared semantic hints come from `x-chio-publish`,
  `x-chio-approval-required`, `x-chio-streaming`, `x-chio-cancellation`, and
  `x-chio-partial-output`.
- `chio-a2a-edge` auto-publishes only `Lossless` and `Adapted` skills. Approval
  and cancellation requirements are treated as `Unsupported`; side effects and
  collated streaming/partial-output semantics are exposed as `Adapted`
  caveats.
- `chio-acp-edge` auto-publishes only `Lossless` and `Adapted` capabilities.
  Browser projections and generic mutating tools are treated as
  `Unsupported`; permission-preview, generic-tool-category, and collected
  streaming semantics are exposed as `Adapted` caveats.

This same discipline should apply to security claims. Chio should never present
"discoverable on MCP" as equivalent to "governed across the full runtime path"
when meaningful A2A, ACP-Client, or native execution paths remain outside the same
kernel/evidence model.

## 5. Cross-Protocol Discovery

A single deployment runs all three edges backed by one kernel and one set
of manifests.

| Protocol | Discovery Mechanism | Served By |
|----------|-------------------|-----------|
| MCP | `tools/list` JSON-RPC | `chio-mcp-edge` |
| A2A | `GET /.well-known/agent-card.json` | `chio-a2a-edge` |
| ACP-Client | `initialize` response | `chio-acp-edge` |

An optional unified `GET /chio/discover` endpoint (outside the edge crates)
can aggregate all surfaces into a single JSON response listing each tool
and its MCP, A2A, and ACP-Client endpoints.

## 6. Architecture Diagram

```
                       Outward (edge)                              Inward (adapter)

MCP Client <--stdio/http--> chio-mcp-edge --+              +-- chio-mcp-adapter <--stdio--> MCP Server
                                           |              |
A2A Client <--http/json-->  chio-a2a-edge --+-- Chio Kernel-+-- chio-a2a-adapter <--http-->  A2A Agent
                                           |              |
ACP-Client Editor <--stdio-->      chio-acp-edge --+              +-- chio-acp-proxy   <--stdio--> ACP-Client Agent
                                           |
                                    [guards, budgets,
                                     receipts, caps]
```

Request flow (same pattern for all three edges):

```
Protocol Client          chio-*-edge               Chio Kernel           Tool Server
    |                        |                        |                     |
    |-- protocol request --->|                        |                     |
    |                        |-- resolve binding      |                     |
    |                        |-- build ToolCallOp     |                     |
    |                        |-- process_session_op-->|                     |
    |                        |                        |-- validate cap      |
    |                        |                        |-- run guards        |
    |                        |                        |-- invoke ---------->|
    |                        |                        |<-- result ---------|
    |                        |                        |-- sign receipt      |
    |                        |<-- SessionOpResponse---|                     |
    |<-- protocol response---|                        |                     |
```

## 7. Implementation Priority

### Build `chio-a2a-edge` first.

1. **Ecosystem demand.** A2A has broad adoption (Google, LangChain,
   CrewAI). Exposing Chio tools as A2A skills makes them immediately usable
   by any A2A-compatible framework.
2. **Adapter symmetry.** `chio-a2a-adapter` already implements the client
   side. The edge completes the bidirectional bridge; its A2A types and
   parsing code can be reused.
3. **HTTP simplicity.** A2A runs over HTTP. No stdio plumbing or subprocess
   management needed. Simpler to test and deploy.
4. **Incremental streaming.** Blocking `SendMessage` is sufficient for v1.

Security rationale: A2A coverage is one of the clearest ways to avoid reducing
Chio to an MCP-only gateway story. It expands deterministic enforcement and
signed observability to a second major runtime surface.

| Phase | Scope |
|-------|-------|
| 1 | Agent Card generation + authoritative blocking `SendMessage` and deferred-task `SendStreamingMessage` |
| 2 | Compatibility-surface isolation and truthful narrowing of unsupported streaming/task lifecycle |
| 3 | Authentication scheme validation |
| 4 | Future richer lifecycle only if the shared protocol fabric can support it honestly |

### `chio-acp-edge` second.

ACP-Client is newer; the editor ecosystem is still consolidating. `chio-acp-proxy`
provides partial coverage. The edge crate is a cleaner design (acts as the
agent rather than proxying one) but can wait until A2A edge is stable.

Security rationale: ACP-Client matters because developer-local and workstation-resident
agents are often the least visible class of runtime behavior. Long term, ACP-Client
coverage is part of reducing blind spots rather than merely adding another
integration checkbox.

| Phase | Scope |
|-------|-------|
| 1 | authoritative blocking `tool/invoke` plus deferred-task `tool/stream` / `tool/cancel` / `tool/resume` and `session/list_capabilities` / `session/request_permission` preview |
| 2 | Compatibility-surface isolation so passthrough lifecycle behavior cannot be confused with the authoritative path |
| 3 | Stdio/editor transport hardening over the authoritative blocking-plus-deferred-task profile |
| 4 | Future richer lifecycle only if the shared protocol fabric can support it honestly |
