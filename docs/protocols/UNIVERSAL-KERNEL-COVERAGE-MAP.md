# Universal Security Kernel: Integration Coverage Map

> **Status**: Research synthesis -- April 2026, **amended** after review
> **Purpose**: Complete mapping of integration surfaces required for Chio to
> function as a universal security kernel for AI agent systems. Synthesized
> from eight parallel research streams covering agent frameworks, data layer,
> code execution, SaaS/communications, networking, edge/WASM, security
> infrastructure, and competitive landscape.
>
> **Priority reconciliation note (post-review):** The priorities in section 2
> of this document were the INITIAL research output. The review cycle
> (REVIEW-FINDINGS-AND-NEXT-STEPS.md) adjusted several priorities based on
> production pattern analysis, DX review, and red-team findings. Where this
> document and the review findings disagree, **the review findings take
> precedence**. Key changes:
> - Human-in-the-loop: P2 -> **P0** (needed by 6/10 production patterns)
> - Package publishing (PyPI/npm): unlisted -> **P0** (adoption blocker)
> - MockChioClient / test fixtures: unlisted -> **P0** (blocks framework work)
> - chio-code-agent adapter: P1 -> **P0** (best onboarding path)
> - TOCTOU execution nonces: unlisted -> **P1** (structural security gap)
> - Emergency kill switch: unlisted -> **P1** (no global circuit breaker)
>
> **Type evolution note:** Multiple docs in this corpus propose new
> `ToolAction` variants and `Constraint` variants with incompatible shapes.
> Before executing any type changes, see ADR-TYPE-EVOLUTION.md for the
> canonical enum definitions. Individual doc proposals are design sketches,
> not the final contract.

---

## 1. Coverage Overview

### What Chio Already Covers

```
PROTOCOL LAYER (shipped)
  MCP | A2A | ACP | OpenAI | Native | HTTP

FRAMEWORK LAYER (shipped)
  FastAPI | Django | ASGI | Express | Fastify | Elysia | Gin | Spring Boot
  ASP.NET | Tower/Axum | Go net/http

INFRASTRUCTURE LAYER (shipped)
  K8s (CRD + webhooks) | SPIFFE/SPIRE | SIEM (Splunk, Elastic)
  OAuth 2.0 + DPoP | SCIM | mTLS | Evidence export

SECURITY LAYER (shipped)
  Guard pipeline (WASM) | Policy engine (HushSpec) | Budget/metering
  Velocity guards | Shell/path/egress guards | Receipt Merkle chain
```

### What This Research Identified as Missing

```
ORCHESTRATION (docs written, not built)
  Temporal | LangGraph | Prefect | Dagster | Airflow | Ray

COMPUTE (docs written, not built)
  AWS Lambda | Cloud Run/ECS sidecars | K8s Jobs

STREAMING (doc written, not built)
  Kafka | NATS | Pulsar | EventBridge | Pub/Sub | Redis Streams

INFRASTRUCTURE AS CODE (doc written, not built)
  Terraform | Pulumi | Crossplane | CDK

AGENT FRAMEWORKS (newly identified)
  CrewAI | AutoGen | LlamaIndex | Vercel AI SDK | Semantic Kernel
  Pydantic AI | OpenAI Swarm | DSPy | Haystack

DATA LAYER (newly identified)
  SQL databases | Vector databases | Data warehouses | NoSQL
  Graph databases | Search engines | Cache/session stores

CODE EXECUTION (newly identified)
  E2B | Modal | Browser automation | Shell/SSH | Notebooks

SAAS / COMMUNICATION (newly identified)
  Slack | Email | PagerDuty | Stripe | Jira | GitHub API
  Salesforce | Google Workspace

NETWORKING (newly identified)
  Envoy ext_authz | API gateways | gRPC interceptors | GraphQL
  WebSocket | Service mesh

DEPLOYMENT SURFACES (newly identified)
  WASM kernel | Mobile (iOS/Android) | Desktop agents
  Browser extensions | IoT/edge | LLM runtime embedding

SECURITY INFRASTRUCTURE (gap analysis)
  Vault/KMS | OPA/Cedar adapters | OCSF format | HSM backend
  Cloud guardrail interop | Compliance framework mappings

CONTENT SAFETY (critical gap)
  ML-based prompt injection | Cloud provider guardrails
  LLM input/output content plane governance
```

---

## 2. Priority Matrix

### P0 -- Critical for "universal kernel" claim

| Integration | Why | Type | Effort |
|-------------|-----|------|--------|
| **Envoy ext_authz** | Single adapter puts Chio into every Istio/Envoy mesh. Chio's sidecar HTTP endpoint is 80% there. | Networking | Small |
| **Content safety guards** | OWASP #1 risk. Chio guards tool access but not LLM content plane. Need ML classifier guard adapters (Lakera, NeMo, Bedrock Guardrails, Azure Content Safety). | Security | Medium |
| **WASM kernel build** | Biggest surface multiplier. Unlocks browser, edge workers, mobile, extensions. `chio-core-types` is already WASM-ready; kernel needs feature flags to drop tokio/rusqlite. | Platform | Large |
| **Cloud guardrail interop** | Enterprise adoption blocker. Adapters for Bedrock Guardrails, Azure Content Safety, Vertex AI safety that consume their verdicts as `GuardEvidence`. | Security | Medium |
| **Code execution governance** | Every agent framework supports code execution (E2B, Modal, Code Interpreter). Need `CodeExecution` and `BrowserAction` variants in `ToolAction`. | Data model | Medium |
| **Temporal integration** | Durable agent workflows are the production standard. Activity interceptor + workflow grants. | Orchestration | Medium |

### P1 -- High value, clear path

| Integration | Why | Type | Effort |
|-------------|-----|------|--------|
| **CrewAI** | Largest multi-agent framework. Default trust model is "every agent can do anything" -- exactly what Chio fixes. Tool wrapper + role-scoped capabilities. | Agent framework | Small |
| **AutoGen / AG2** | Microsoft-backed, enterprise adoption. Group chat + tool use is high-risk. Two intercept points: tool execution + agent handoff. | Agent framework | Small |
| **LlamaIndex** | Dominant RAG framework. `AgentRunner` + `FunctionTool` map directly to Chio. Query engine tools carry data-access risk. | Agent framework | Small |
| **Vercel AI SDK** | Dominates TypeScript/Next.js. `tool()` with Zod schemas + streaming. Web-facing agent UIs exposed to end users. | Agent framework | Small |
| **SQL database governance** | Text-to-SQL is everywhere. Need `TableAllowlist`, `OperationClass`, `RowFilter`, `MaxRowsReturned` constraints. | Data layer | Medium |
| **Vector database governance** | Every RAG pipeline. Need `CollectionAllowlist`, `NamespaceExact`, `MaxTopK` constraints. URI pattern: `vector://provider/ns/collection`. | Data layer | Medium |
| **Data warehouse cost governance** | BigQuery/Snowflake cost explosion risk. Pre-execution cost estimation via dry-run APIs + `MaxBytesScanned` constraint. | Data layer | Medium |
| **Kong/Traefik/NGINX** | ForwardAuth / auth_request to Chio sidecar. Covers self-hosted API gateway market. | Networking | Small |
| **gRPC interceptors** | Thin clients (Python/Go/Java) calling sidecar. Per-stream evaluation. | Networking | Small |
| **AWS Lambda** | Lambda Extension model. Serverless tool servers. | Compute | Medium |
| **Communication platforms** | Slack, email, SMS. Agent messages are visible to humans and hard to reverse. Content-review guards mandatory. | SaaS | Medium |
| **Payment APIs** | Stripe, Plaid. Direct monetary risk. Amount limits, transaction type restrictions, mandatory approval above thresholds. | SaaS | Medium |
| **Desktop agent scoping** | Claude Desktop, Cursor, VS Code. Per-application capability scoping. Near-term deployment reality. | Platform | Small |
| **Model routing governance** | Capability tokens should constrain which LLM model can drive tool calls. Need `model_constraint` on `ToolGrant`. | Architecture | Medium |
| **LangGraph** | Extends existing chio-langchain. Graph-level scoping, delegation, approval nodes. | Orchestration | Medium |
| **Vault/KMS integration** | `VaultCapabilityAuthority` implementing existing trait. HSM for receipt signing keys. | Security | Medium |
| **Terraform/Pulumi** | Highest-blast-radius tool call. Plan/apply as two-phase capability. | IaC | Medium |
| **Kafka/event streaming** | Choreography governance. Consumer-side evaluation, transactional receipts, DLQ as security signal. | Streaming | Medium |
| **NIST AI RMF / ISO 42001 mapping** | Enterprise procurement requires it. Chio likely already satisfies most controls; needs explicit mapping docs. | Compliance | Small |

### P2 -- Important, can follow

| Integration | Why | Type | Effort |
|-------------|-----|------|--------|
| Semantic Kernel | Enterprise .NET/Java. Plugin/KernelFunction model. Plan-level evaluation is unique. | Agent framework | Small |
| Pydantic AI | Growing, clean DI model for Chio context. | Agent framework | Small |
| OpenAI Swarm | Minimal but handoff-as-delegation is natural Chio fit. | Agent framework | Small |
| Prefect / Dagster / Airflow | ML pipeline orchestrators. Decorator-based integration. | Orchestration | Medium |
| Ray | Distributed agent swarms. Actor-level standing grants. | Compute | Medium |
| GraphQL | Operation-level middleware. Query complexity as budget. | Networking | Medium |
| WebSocket/SSE | Connection-level grants with TTL. Mid-session revocation. | Networking | Small |
| Graph databases | Traversal depth limits, node/edge type scoping. | Data layer | Small |
| Search engines | Index-level scoping. Lower risk (read-only). | Data layer | Small |
| NoSQL databases | Collection-level capabilities, operation class. | Data layer | Small |
| Browser automation | Domain allowlists, action-type restrictions, credential detection. | Code execution | Medium |
| Mobile (iOS/Android) | Embedded library via UniFFI. Offline evaluation, receipt sync. | Platform | Large |
| Browser extensions | WASM kernel in service worker. Chrome permissions map to Chio scopes. | Platform | Medium |
| OPA/Cedar adapters | Guard that delegates policy evaluation to OPA/Rego or Cedar. | Security | Small |
| OCSF receipt format | Receipts natively queryable in OCSF-aware SIEMs. | Security | Small |
| LangSmith/LangFuse adapters | Push receipts as enriched spans into existing observability. | Observability | Small |
| ~~Human-in-the-loop protocol~~ | **Moved to P0.** See REVIEW-FINDINGS-AND-NEXT-STEPS.md section 7 and HUMAN-IN-THE-LOOP-PROTOCOL.md. Needed by 6/10 production patterns. | Architecture | Medium |
| Agent SLAs | Timeout budgets, retry policy, penalty receipts for tool servers. | Architecture | Medium |
| Monitoring/incident (PagerDuty) | Agents that can page humans need severity-level caps. | SaaS | Small |
| Project management (Jira, Linear) | Read vs write scoping, transition guards. | SaaS | Small |
| Version control (GitHub API) | Repo/branch scoping, merge restrictions. | SaaS | Small |
| K8s Jobs/CronJobs | Job-level capability lifecycle, receipt aggregation. | Compute | Medium |
| Cloud Run/ECS sidecars | Reference deployment patterns, not new SDKs. | Compute | Small |

### P3 -- Future / niche

| Integration | Why | Type |
|-------------|-----|------|
| DSPy | Programming model, not tool-call-centric. | Agent framework |
| Haystack | Pipeline model, fewer trust boundaries. | Agent framework |
| Bee / Mastra | Low adoption. | Agent framework |
| IoT/edge devices | Small market, strongest security argument. | Platform |
| LLM runtime embedding | High leverage but requires per-runtime integration. | Platform |
| Linkerd | No ext_authz equivalent; P2 at best. | Networking |
| Cloudflare Workers WASM | Depends on WASM kernel work. | Networking |
| RPA (UiPath) | Not yet common in LLM agent loops. | Code execution |
| Notebook execution | Special case of code execution. | Code execution |
| Cache/session stores | Key-prefix scoping, low risk. | Data layer |
| Object storage as data | URI pattern scoping already works. | Data layer |
| Ansible | Configuration management, same threat model as IaC. | IaC |
| Crossplane | Extends K8s integration. | IaC |

---

## 3. Architectural Gaps (Not Just Integrations)

The research identified several gaps that require new Chio primitives, not
just adapter code:

### 3.1 Content Plane Governance

Chio governs the **control plane** (which tools can be called, by whom,
with what scope). It does not govern the **content plane** (what the LLM
says, what it sends, what data flows through tool results).

```
Current Chio coverage:

  LLM -> [???] -> tool call -> [Chio kernel] -> tool server -> result -> [???] -> LLM
          ^                                                               ^
          |                                                               |
     NOT GOVERNED                                                   NOT GOVERNED
     (prompt injection,                                             (PII in results,
      jailbreak, toxic)                                              exfiltration)
```

Required additions:
- **Pre-invocation content guards**: ML classifiers scanning tool call
  arguments for prompt injection, data exfiltration patterns
- **Post-invocation result guards**: PII detection, data redaction,
  result size limiting on tool responses before they reach the agent
- **Guard adapters for cloud safety APIs**: Bedrock, Azure, Vertex

The guard pipeline already supports this (pre and post evaluation hooks
exist). The gap is ML-backed guard implementations and cloud provider
adapters.

### 3.2 New `ToolAction` Variants

The `ToolAction` enum in `chio-guards` needs extension:

```rust
pub enum ToolAction {
    // Existing
    ShellCommand { .. },
    FileAccess { .. },
    FileWrite { .. },
    NetworkEgress { .. },
    Patch { .. },

    // Needed
    CodeExecution {
        language: String,
        code_hash: String,
        network_access: bool,
        max_execution_seconds: u64,
    },
    BrowserAction {
        action_type: BrowserActionType,  // Navigate, Click, Type, Screenshot
        url: Option<String>,
        selector: Option<String>,
    },
    DatabaseQuery {
        engine: DatabaseEngine,  // Postgres, MySQL, BigQuery, etc.
        operation_class: OperationClass,  // ReadOnly, ReadWrite, DDL
        tables: Vec<String>,
        estimated_cost: Option<f64>,
    },
    ExternalApiCall {
        service: String,  // "slack", "stripe", "github"
        action: String,   // "post_message", "charge", "create_pr"
        visibility: Visibility,  // Internal, External, Financial
    },
}
```

### 3.3 New `Constraint` Variants

```rust
pub enum Constraint {
    // Existing
    PathPrefix(String),
    DomainExact(String),
    Regex(String),
    MaxLength(usize),
    Custom(String, String),

    // Needed for data layer
    TableAllowlist(Vec<String>),
    CollectionAllowlist(Vec<String>),
    OperationClass(OperationClass),  // ReadOnly, ReadWrite, DDL
    MaxRowsReturned(u64),
    MaxBytesScanned(u64),
    MaxCostPerQuery(f64),
    ColumnProjection(Vec<String>),   // Allowed columns

    // Needed for model routing
    ModelConstraint {
        allowed_models: Vec<String>,
        allowed_providers: Vec<String>,
    },

    // Needed for communication
    RecipientAllowlist(Vec<String>),
    ContentReviewRequired(bool),
    MaxRecipientsPerWindow(u64),

    // Needed for financial
    MaxAmountPerTransaction(f64),
    AllowedCurrencies(Vec<String>),
    RequireApprovalAbove(f64),
}
```

### 3.4 Portable Kernel (`chio-kernel-core`)

The biggest architectural unlock: a feature-flagged kernel build that
compiles to WASM, mobile, and embedded targets.

```
Current kernel dependencies:
  tokio         -> async runtime (not available in WASM/embedded)
  rusqlite      -> receipt persistence (not available in WASM)
  ureq          -> HTTP client for price oracles (not available in WASM)
  OsRng         -> entropy (available via getrandom js/wasi features)

Proposed split:
  chio-kernel-core (no_std + alloc)
    - Capability validation
    - Scope checking
    - Guard pipeline (sync)
    - Receipt signing (ed25519 + sha2 work in WASM)
    - In-memory receipt buffer
    - Pure computation, zero I/O

  chio-kernel (full, current)
    - Depends on chio-kernel-core
    - Adds tokio, rusqlite, ureq
    - Adds HTTP server, persistent storage, async guards

Targets:
  wasm32-unknown-unknown  -> browser agents, edge workers
  wasm32-wasi             -> WASI runtimes (Wasmtime, WasmEdge)
  aarch64-apple-ios       -> iOS agents
  aarch64-linux-android   -> Android agents
  thumbv7em-none-eabihf   -> Cortex-M embedded (stretch)
```

### 3.5 Plan-Level Evaluation

Several frameworks (Semantic Kernel planners, CrewAI task planning,
LangGraph graph compilation) create multi-step execution plans before
running them. Chio currently evaluates per-tool-call. A new evaluation
mode would evaluate the plan holistically:

```
Agent submits: "I plan to call tools A, B, C in sequence"
Chio evaluates: "You have capability for A and B but not C"
Result: Plan rejected before execution begins
```

This prevents wasted work and provides earlier feedback. The `chio-workflow`
crate's `SkillManifest` with declared steps is the foundation, but it
needs to integrate with framework-specific plan formats.

---

## 4. The Integration Pattern Taxonomy

Across all surfaces researched, Chio integrations follow one of five
patterns. Any new integration should identify which pattern it uses:

### Pattern 1: Tool Execution Wrapper
**Used by:** Agent frameworks (CrewAI, AutoGen, LlamaIndex, Vercel AI SDK),
  data layer (SQL, vector DB), code execution (E2B, Modal)
**How:** Wrap the framework's tool/function execution with a Chio
  `evaluate()` call before and `record()` call after.
**Chio artifact:** `chio-{framework}` SDK package.

### Pattern 2: Middleware / Interceptor
**Used by:** HTTP frameworks (FastAPI, Express), gRPC, API gateways,
  service mesh (Envoy ext_authz)
**How:** HTTP/gRPC middleware that intercepts requests, calls sidecar,
  injects receipt headers on response.
**Chio artifact:** Middleware library or gateway plugin.

### Pattern 3: Lifecycle Controller
**Used by:** Orchestrators (Temporal, Airflow), K8s Jobs, Lambda,
  Cloud Run, event streaming
**How:** Controller that manages capability grant lifecycle: acquire
  on start, evaluate per-step, release on completion, aggregate receipts.
**Chio artifact:** Interceptor/controller + lifecycle hooks.

### Pattern 4: Delegation Chain
**Used by:** Multi-agent frameworks (CrewAI crews, AutoGen group chats,
  LangGraph supervisor/worker, OpenAI Swarm handoffs)
**How:** When agent A delegates to agent B, capabilities are attenuated.
  Child agent's scope is a subset of parent's scope.
**Chio artifact:** Delegation primitives on existing capability model.

### Pattern 5: Platform Adapter
**Used by:** WASM, mobile, desktop, browser extensions, IoT
**How:** Compile Chio kernel to target platform. Provide platform-specific
  I/O adapters (storage, entropy, networking).
**Chio artifact:** `chio-kernel-core` + platform binding crate.

---

## 5. Revised Tier Classification

Based on the full research, the original tier classification should be
updated. Some "skip" items are now critical, and some new categories
emerged:

### Must-Build (defines "universal kernel")
1. Envoy ext_authz adapter
2. Content safety guard adapters (ML classifiers + cloud provider interop)
3. WASM kernel build (chio-kernel-core)
4. Temporal integration
5. Top 4 agent frameworks (CrewAI, AutoGen, LlamaIndex, Vercel AI SDK)
6. Data layer constraints (SQL, vector DB, warehouse cost governance)
7. Code execution governance (ToolAction extensions)
8. Event streaming (Kafka consumer-side + transactional receipts)
9. Terraform/Pulumi (highest-blast-radius tool call)

### Should-Build (expected of a security kernel)
10. AWS Lambda Extension
11. LangGraph (extends existing LangChain work)
12. Communication + payment governance (Slack, Stripe)
13. API gateway plugins (Kong, Traefik)
14. gRPC interceptors
15. Desktop agent scoping
16. Vault/KMS integration
17. OPA/Cedar guard adapters
18. Model routing constraints
19. NIST/ISO compliance mappings

### Will-Build (completes the surface)
20. Prefect / Dagster / Airflow
21. Ray distributed compute
22. Mobile (iOS/Android) embedded kernel
23. Browser extension kernel
24. GraphQL / WebSocket
25. Remaining SaaS adapters (Jira, GitHub, PagerDuty)
26. LangSmith/LangFuse observability bridge
27. Human-in-the-loop protocol
28. Agent SLA primitives
29. OCSF receipt format
30. K8s Jobs / Cloud Run reference patterns
