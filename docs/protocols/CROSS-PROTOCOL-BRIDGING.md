# Cross-Protocol Bridging


> **Status**: Chio now ships a shared `chio-cross-protocol` substrate with a real
> `CrossProtocolOrchestrator`, `CapabilityBridge`, capability-envelope, and
> bridge-lineage model. The current implementation is the authoritative
> edge-to-native execution substrate used by the A2A/ACP-Client lanes.
>
> **Remaining future work**: The fuller bridge-registry and multi-hop
> protocol-to-protocol fabric sketched in this document is still future
> architecture. The shipped runtime now includes protocol-aware target binding
> metadata and executor selection for the supported authoritative edges, but it
> is not yet the final universal orchestrator end-state.

---

## 1. Vision

Agent ecosystems are fragmenting across MCP, A2A, and ACP-Client. Each defines its
own tool/skill/capability model, invocation envelope, and trust assumptions.
Tool authors implement three adapters, operators run three control planes,
and audit trails scatter across incompatible formats.

Chio aims to reduce this fragmentation by serving as a governed cross-protocol
bridge. A tool published once through Chio can be made consumable via MCP, A2A,
and ACP-Client surfaces when the semantic projection is faithful enough to preserve
Chio's security and execution guarantees. Every bridged invocation passes
through the same kernel in the shipped edge-helper paths. The generic
orchestrator sketched here is the next architectural step, not a current
runtime claim.

```
                   +------------------+
                   |   Tool Server    |
                   | (registered once)|
                   +--------+---------+
                            |
                    Chio Kernel (TCB)
                  /    |    |    \
           +-----+ +------+ +------+ +------+
           | MCP | | A2A  | | ACP-Client  | |Native|
           |Edge | |Adapt.| |Adapt.| |Client|
           +-----+ +------+ +------+ +------+
```

One tool, three protocol surfaces, unified security, unified receipts.

### 1.1 Why MCP-Only Coverage Is Structurally Incomplete

Wrapped MCP edges are useful because they create a deterministic enforcement
point for a large class of current agent-to-tool traffic. They are not enough
on their own.

Reasons:

- agent execution can move to A2A task exchange, ACP-Client editor sessions, or native
  function/API surfaces
- session meaning is distributed across workflow history, delegation lineage,
  approvals, and tool sequences rather than a single isolated tool call
- observability without enforcement is reactive, while enforcement without
  enough context can be brittle or misleading

Cross-protocol bridging is therefore not just a feature-expansion story. It is
part of closing the gap between "we secure one protocol boundary" and "we
govern the runtime behavior that actually matters."

---

## 2. Protocol Translation Layer

### 2.1 Concept Alignment

| Chio               | MCP                  | A2A                | ACP-Client                  |
|--------------------|----------------------|--------------------|----------------------|
| Tool               | Tool                 | Skill              | Capability/Function  |
| ToolManifest       | tools/list response  | AgentCard.skills   | capabilities object  |
| ToolCallRequest    | tools/call           | SendMessage        | tool_calls[]         |
| ToolCallResponse   | tools/call result    | Task artifact      | tool_results[]       |
| CapabilityToken    | (none)               | (none)             | (none)               |
| ChioReceipt         | (none)               | (none)             | (none)               |

Capability tokens and receipts have no external equivalents. Chio adds these
security properties transparently at the bridge layer.

### 2.1.1 Deterministic Governance, Observability, and Dynamic Governance

Cross-protocol design should preserve three distinct layers:

- **Deterministic governance**: capability checks, guard evaluation, budget
  enforcement, revocation, allow/deny decisions
- **Continuous observability**: signed receipts, trace context, lineage,
  sequence integrity, evidence bundles
- **Dynamic governance**: optional future decisions that incorporate live risk
  or intent signals

The bridge layer must not pretend to provide layer 3 merely because it can
translate layer 1 and emit layer 2 artifacts.

### 2.2 MCP <-> A2A

**Discovery (MCP -> A2A):** Each MCP tool becomes an A2A skill in a
synthesized Agent Card.

```rust
fn mcp_tool_to_a2a_skill(tool: &ToolDefinition, server_id: &str) -> A2aSkill {
    A2aSkill {
        id: format!("{}/{}", server_id, tool.name),
        name: tool.name.clone(),
        description: tool.description.clone(),
        input_modes: vec!["application/json".into()],
        output_modes: vec!["application/json".into()],
    }
}
```

**Invocation (A2A -> MCP):** Extract `chio.targetSkillId` from metadata,
parse `DataPart` as MCP arguments, forward as `tools/call`, wrap result as
A2A `Task` with `DataPart` artifact.

### 2.3 MCP <-> ACP-Client

**Discovery (MCP -> ACP-Client):** Each MCP tool becomes an ACP-Client capability.

```rust
fn mcp_tool_to_acp_capability(tool: &ToolDefinition) -> AcpCapability {
    AcpCapability {
        name: tool.name.clone(),
        description: tool.description.clone(),
        parameters: tool.input_schema.clone(),
    }
}
```

**Invocation (ACP-Client -> MCP):** ACP-Client `tool_calls` translates directly to MCP
`tools/call`. Both use JSON Schema for parameters.

### 2.4 A2A <-> ACP-Client

**Discovery (A2A -> ACP-Client):** Each A2A skill becomes an ACP-Client capability.
Skill `inputModes`/`outputModes` are recorded in adapter metadata.

**Invocation (ACP-Client -> A2A):** ACP-Client `tool_calls` repackaged as A2A
`SendMessage` with `DataPart` arguments and `chio.targetSkillId` metadata.

### 2.5 Type Mapping

| MCP Type         | A2A Type            | ACP-Client Type             |
|------------------|---------------------|----------------------|
| TextContent      | TextPart            | text content block   |
| ImageContent     | FilePart (inline)   | image content block  |
| EmbeddedResource | DataPart            | tool_results[].output|
| isError: true    | Task.status: failed | error content block  |
| ProgressToken    | Task.status: working| (stream signal)      |

### 2.6 Semantic Conformance Matrix

Not every tool maps cleanly across MCP calls, A2A tasks, and ACP-Client sessions. Chio
should only auto-publish a tool on a target protocol when the projection is
either lossless or explicitly caveated.

| Concern | MCP | A2A | ACP-Client | Bridge rule |
|---------|-----|-----|-----|-------------|
| Invocation shape | Direct request/response | Task-oriented, may be long-lived | Session-scoped prompt/capability flow | Reject publication when the target protocol cannot represent lifecycle semantics honestly |
| Streaming | Progress tokens / chunked tool output | Task status + artifact streaming | Session updates / notifications | Mark as adapted when streaming must be down-leveled |
| Cancellation | Client/task cancellation | Task cancellation | Session cancellation | Expose only if cancellation semantics can be mapped or clearly caveated |
| Permission prompts | Usually external to protocol | Usually external to protocol | First-class permission requests | ACP-Client surfaces may require adapted mode when tool side effects need interactive approval |
| Side-effect visibility | Tool metadata only | Skill metadata + task status | Capability metadata + session events | Preserve side-effect labeling on every bridged surface |
| Partial output | Natural | Natural | Depends on session/update contract | Reject auto-bridge if partial output would be silently dropped |

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeFidelity {
    Lossless,
    Adapted { caveats: Vec<String> },
    Unsupported { reason: String },
}
```

Every outward edge should compute a per-tool `BridgeFidelity` before automatic
publication. `Unsupported` tools stay local to their source protocol.

The shipped `chio-cross-protocol` substrate now derives these decisions from a
shared semantic-hint pass over tool schemas:

- `x-chio-publish: false` gates publication entirely.
- `x-chio-approval-required` marks projections that need honest interactive
  approval semantics.
- `x-chio-streaming`, `x-chio-cancellation`, and `x-chio-partial-output` express
  lifecycle guarantees that must either survive the bridge or be surfaced as
  caveats.
- `x-chio-target-protocol` records the intended authoritative target protocol
  for a published outward binding (`native`, `mcp`, `http`, `a2a`, `acp`,
  `open_ai`). Unsupported values fail closed.

Current truthful publication rules are intentionally conservative:

- A2A marks tools as `Unsupported` when they require interactive approval or
  cancellation semantics the current task surface cannot represent honestly.
- A2A marks tools as `Adapted` when side-effect, streaming, or partial-output
  semantics are preserved only through final task payloads rather than native
  incremental lifecycle events.
- ACP-Client marks browser capabilities and generic mutating tools as `Unsupported`
  because the current ACP-Client edge cannot project those authority semantics
  truthfully.
- ACP-Client marks generic read-only tools, permission-preview-dependent tools, and
  collected streaming outputs as `Adapted` with explicit caveats in outward
  discovery metadata.

---

## 3. Capability Propagation Across Protocols

### 3.1 Chain Integrity

When an A2A agent delegates to an MCP tool through Chio, the capability
chain remains intact. The bridge never manufactures authority.

```
  A2A Agent            Chio Kernel         MCP Tool Server
     |                    |                    |
     |-- SendMessage ---->|                    |
     |   (bridge cap ref) |                    |
     |                    |-- validate cap --->|
     |                    |-- tools/call ----->|
     |                    |<- result ----------|
     |                    |-- sign receipt     |
     |<- Task artifact ---|                    |
```

### 3.2 CapabilityBridge Trait

```rust
pub trait CapabilityBridge: Send + Sync {
    fn source_protocol(&self) -> &str;

    /// Extract capability reference from inbound protocol envelope.
    /// None triggers fallback to session-level grants only when the deployment
    /// explicitly enables ambient bridging. Otherwise the bridge denies.
    fn extract_capability_ref(
        &self,
        request: &serde_json::Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError>;

    /// Inject Chio capability into outbound protocol envelope.
    fn inject_capability_ref(
        &self,
        envelope: &mut serde_json::Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolCapabilityRef {
    pub chio_capability_id: String,
    pub origin_protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_context: Option<serde_json::Value>,
    pub parent_capability_hash: String,
}
```

### 3.3 Capability Envelope

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolCapabilityEnvelope {
    pub schema: String,  // "chio.cross-protocol-cap.v1"
    pub capability: CapabilityToken,
    pub target_protocol: String,
    /// Must be a strict subset of capability.scope.
    pub attenuated_scope: ChioScope,
    pub bridged_at: u64,
    pub bridge_id: String,
}
```

### 3.4 Attenuation

Sub-capabilities crossing protocol boundaries are strictly narrower than
the parent. The bridge computes the intersection of the parent's `ChioScope`
with the target tool's requirements:

```rust
fn attenuate_for_bridge(
    parent_scope: &ChioScope,
    target_server: &str,
    target_tool: &str,
) -> Option<ChioScope> {
    let matching: Vec<ToolGrant> = parent_scope.grants.iter()
        .filter(|g| g.server_id == target_server && g.tool_name == target_tool)
        .cloned()
        .collect();
    if matching.is_empty() {
        return None; // Fail closed.
    }
    Some(ChioScope { grants: matching, resource_grants: vec![], prompt_grants: vec![] })
}
```

The kernel verifies `attenuated_scope.is_subset_of(&parent.scope)` before
admitting any cross-protocol request. Failure produces `Decision::Deny`.

---

## 4. Multi-Protocol Tool Discovery

### 4.1 Unified Registry

```rust
#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    pub canonical_name: String,
    pub protocol: DiscoveryProtocol,
    pub origin: String,
    pub definition: ToolDefinition,
    pub adapter_metadata: AdapterMetadata,
    pub bridge_fidelity: BridgeFidelity,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiscoveryProtocol { Native, Mcp, A2a, Acp }
```

```
  +------------------------------------------------+
  |           UnifiedToolRegistry                   |
  |  HashMap<canonical_name, Vec<DiscoveredTool>>   |
  |                                                 |
  |  "web-search" -> [MCP(srv-a), A2A(agent-b)]    |
  |  "code-exec"  -> [Native(sandbox-1)]            |
  |  "translate"   -> [A2A(agent-c), ACP-Client(svc-d)]    |
  +------------------------------------------------+
```

### 4.2 Query API

```rust
pub trait ToolRegistry: Send + Sync {
    fn query_tools(&self, query: &ToolQuery) -> Vec<&DiscoveredTool>;
    fn register(&mut self, tool: DiscoveredTool);
    fn deregister_origin(&mut self, origin: &str);
}

#[derive(Debug, Clone)]
pub struct ToolQuery {
    pub name_pattern: Option<String>,
    pub protocols: Option<Vec<DiscoveryProtocol>>,
    pub scope_filter: Option<ChioScope>,
    pub limit: usize,
}
```

### 4.3 Automatic Multi-Protocol Registration

Registration through any adapter attempts to generate all three external
representations at registration time (not query time), but only publishes
surfaces whose fidelity is `Lossless` or `Adapted`:

```
  Register "analyze-code" via Chio native API
     |
     +-> MCP: tools/list entry     (published if fidelity != Unsupported)
     +-> A2A: AgentCard skill      (published if fidelity != Unsupported)
     +-> ACP-Client: capability entry     (published if fidelity != Unsupported)
```

---

## 5. Receipt Correlation

### 5.1 Trace Context

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolTraceContext {
    pub trace_id: String,
    pub hops: Vec<ProtocolHop>,
    pub session_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHop {
    pub protocol: String,
    pub receipt_id: String,
    pub bridge_id: String,
    pub timestamp: u64,
}
```

### 5.2 Receipt Tree

Receipts form a parent-child tree across protocol boundaries:

```
  ChioReceipt (root: A2A inbound)
    +-- ChioReceipt (bridge: A2A -> kernel)
    |     +-- ChioReceipt (kernel -> MCP tool)
    +-- ChildRequestReceipt (sampling callback)
```

The `CrossProtocolTraceContext` is embedded in each receipt's `metadata`
field. The receipt query API supports `trace_id` filters to reconstruct
the full cross-protocol call tree.

### 5.3 Session Fingerprint

```
SHA-256(canonical_json_bytes({
  "session_id": session_id,
  "initiating_protocol": initiating_protocol,
  "initiating_agent_key": initiating_agent_key,
  "workflow_start_ts": workflow_start_ts
}))
```

Binds all receipts from a logical workflow together, even across kernel
instances in federated deployments.

---

## 6. Multi-Protocol Agent Orchestrator

### 6.1 Architecture

```rust
pub struct CrossProtocolOrchestrator {
    registry: Box<dyn ToolRegistry>,
    bridges: HashMap<DiscoveryProtocol, Box<dyn CapabilityBridge>>,
    kernel: Chio<ChioKernel>,
    active_traces: HashMap<String, CrossProtocolTraceContext>,
}
```

The shipped runtime now implements the substrate-level form of this idea in
`chio-cross-protocol`: a real orchestrator, capability-envelope contract,
trace-lineage model, and protocol executor registry seam. The current
authoritative edges use shared bridge metadata plus that executor seam to
select supported targets such as `native` and `mcp` without hardcoding every
call to `Native`.

The broader architecture shown here is still future work in one main way:

1. the executor/bridge registry is now a shipped intent-aware control-plane
   substrate for the qualified authoritative surfaces, but it is not yet a
   claim that every protocol family or partner ecosystem in the long-range
   research is already integrated or qualified

### 6.2 Flow: A2A -> MCP -> ACP-Client

```
  A2A Agent         Orchestrator          MCP Server    ACP-Client Agent
     |                  |                     |             |
     |-- SendMessage -->|                     |             |
     |                  |-- validate cap ---->|             |
     |                  |-- tools/call ------>|             |
     |                  |<- result -----------|             |
     |                  |-- receipt (hop 1)   |             |
     |                  |-- attenuate cap --->|             |
     |                  |-- tool_calls[] -----|------------>|
     |                  |<- tool_results[] ---|-------------|
     |                  |-- receipt (hop 2)   |             |
     |                  |-- unified receipt   |             |
     |<- Task artifact -|                     |             |
```

This example illustrates why protocol breadth matters. An organization could
enforce MCP at the inner hop and still miss material runtime context unless the
outer A2A and ACP-Client hops are tied into the same kernel and receipt graph.

### 6.3 Unified Receipt

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProtocolReceipt {
    pub root_receipt: ChioReceipt,
    pub hop_receipts: Vec<ChioReceipt>,
    pub trace: CrossProtocolTraceContext,
    /// Allow only if every hop allowed.
    pub aggregate_decision: Decision,
}
```

### 6.4 Error Handling

1. **Fail-closed propagation.** The orchestrator does not attempt the next
   hop after a failure. Partial results are discarded.
2. **Denial receipt.** `Decision::Deny` receipt emitted for the failing
   hop, citing bridge adapter and failure reason.
3. **Rollback receipts.** Best-effort cancellation receipts for completed
   hops if the tool supports idempotent undo.
4. **Caller notification.** Error in the originating protocol's native
   format (MCP error, A2A failed task, ACP-Client error content block).

---

## 7. Latency-Aware Routing

### 7.1 Adapter Metadata

```rust
#[derive(Debug, Clone)]
pub struct AdapterMetadata {
    pub latency_p50_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
    pub success_rate: Option<f64>,
    pub observation_count: u64,
    pub authoritative: bool,
    pub last_updated: u64,
}
```

### 7.2 Routing Policies

```rust
#[derive(Debug, Clone, Copy)]
pub enum RoutingPolicy {
    /// Lowest p50 latency. Ties broken by success rate.
    BestEffort,
    /// Highest success rate, ignoring latency.
    Critical,
    /// Prefer authoritative adapter. Fall back to BestEffort.
    Authoritative,
}

fn select_adapter<'a>(
    candidates: &'a [DiscoveredTool],
    policy: RoutingPolicy,
) -> Option<&'a DiscoveredTool> {
    match policy {
        RoutingPolicy::BestEffort => candidates.iter()
            .min_by_key(|c| c.adapter_metadata.latency_p50_ms.unwrap_or(u64::MAX)),
        RoutingPolicy::Critical => candidates.iter()
            .max_by(|a, b| {
                let ra = a.adapter_metadata.success_rate.unwrap_or(0.0);
                let rb = b.adapter_metadata.success_rate.unwrap_or(0.0);
                ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
            }),
        RoutingPolicy::Authoritative => candidates.iter()
            .find(|c| c.adapter_metadata.authoritative)
            .or_else(|| select_adapter(candidates, RoutingPolicy::BestEffort)),
    }
}
```

### 7.3 Metric Collection

Adapters update metadata after every invocation via exponential moving
average. Metrics are local to each kernel instance; federated aggregation
is a future extension through the evidence-sharing mechanism.

---

## 8. Implementation Roadmap

| Phase | Scope | Depends On |
|-------|-------|------------|
| 1 | Foundation: MCP + A2A adapters (shipped) | -- |
| 2 | `UnifiedToolRegistry`, `DiscoveredTool`, `ToolQuery` API | Phase 1 |
| 3 | Protocol-semantic conformance matrix + `BridgeFidelity` gating | Phase 2 |
| 4 | `chio-acp-adapter` crate, ACP-Client discovery + invocation | Phase 1 |
| 5 | `CapabilityBridge` trait, `CrossProtocolCapabilityEnvelope`, attenuation | Phase 2, 3 |
| 6 | `CrossProtocolTraceContext`, receipt correlation, session fingerprint | Phase 5 |
| 7 | `CrossProtocolOrchestrator`, multi-hop chaining, unified receipts | Phase 5, 6 |
| 8 | `AdapterMetadata` collection, `RoutingPolicy`, latency-aware selection | Phase 2 |
| 9 | Conformance tests, fuzz testing, benchmarks, honest boundary docs | Phase 7, 8 |

The roadmap priority is not "more protocols for completeness theater." It is
"secure the runtime surfaces agents actually use as traffic diversifies beyond
MCP-only architectures."
