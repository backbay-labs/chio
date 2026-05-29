# HTTP Framework Integration Strategy

> **Status**: Strategic direction -- approved April 2026.
> This document defines how Chio extends beyond protocol adapters (MCP, A2A, ACP)
> toward a shared security kernel for supported API surfaces.
>
> **Current-state note:** the repo now ships the core HTTP/kernel substrate:
> `chio api protect`, `chio-openapi`, `chio-sdk-python`, `chio-asgi`,
> `@chio-protocol/node-http`, `chio-go-http`, `chio-tower`,
> `chio-spring-boot`, and `ChioMiddleware`, plus the thin FastAPI/Django and
> Express/Fastify/Elysia wrappers. This document still mixes shipped packaging
> with forward-looking DX direction. Generic cross-protocol orchestration
> remains future architecture, not a shipped runtime.

## 1. The Problem: Chio Is Not "Just Another MCP Gateway"

Chio's current adapter surface covers three agent protocols: MCP (tool access),
A2A (agent-to-agent), and ACP (editor-to-agent). This positions Chio as a
protocol-specific security layer.

But the real surface area is much larger. Agents call APIs. They call FastAPI
endpoints, Django views, Go handlers, Elysia routes, Spring controllers. Every
HTTP API is a tool surface that agents consume. If Chio only secures the three
agent protocols, it misses a large share of the practical attack surface.

The strategic move: **one kernel, many substrates**. Chio's capability tokens,
guard pipeline, and receipt signing should work on HTTP/API surfaces where Chio
has a clear enforcement or observation boundary, not just MCP/A2A/ACP.

## 2. Architecture: Substrates, Not Frameworks

Instead of building N framework integrations from scratch, build a small number
of **substrate adapters** that cover families of frameworks.

```
+---------------------------------------------------------------+
|                    Framework Wrappers (thin)                   |
|  chio-fastapi  chio-django  chio-elysia  chio-fastify  chio-gin    |
+---------------------------------------------------------------+
|                    Substrate Adapters                          |
|  chio-asgi     chio-node-http     chio-go-http     chio-tower     |
+---------------------------------------------------------------+
|                    Shared Core                                 |
|  chio-http-core (request model, session, receipts, policy)     |
+---------------------------------------------------------------+
|                    Chio Kernel                                  |
|  Capabilities  |  Guards  |  Receipts  |  Budgets  |  DPoP    |
+---------------------------------------------------------------+
|                    Protocol Adapters (existing)                |
|  chio-mcp-adapter  |  chio-a2a-adapter  |  chio-acp-proxy        |
+---------------------------------------------------------------+
```

### Substrate Map

| Substrate | Covers | Package |
|-----------|--------|---------|
| ASGI (Python) | FastAPI, Starlette, Litestar, async Python | `chio-asgi` |
| WSGI/Django (Python) | Django, DRF, Flask (WSGI + ORM patterns) | `chio-django` |
| Node/Bun HTTP (JS/TS) | Fastify, Express, Nest, Hono, Elysia | `@chio-protocol/node-http` |
| net/http (Go) | stdlib, Gin, Echo, Fiber, chi | `chio-go-http` |
| Servlet/WebFlux (Java) | Spring Boot, Quarkus, Micronaut | `chio-jvm` |
| ASP.NET Core (.NET) | Minimal APIs, MVC, Blazor | `chio-dotnet` |
| tower::Layer (Rust) | Axum, Tonic, any tower-based service | `chio-tower` |

### Why Substrates Work

- **ASGI** is the standard async Python interface. FastAPI and Starlette are
  ASGI apps. One ASGI middleware covers the entire async Python API ecosystem.
  Django gets its own package because WSGI, the ORM, and admin patterns are
  structurally different.

- **Node/Bun HTTP** has a common `(req, res)` or `Request -> Response` model.
  One substrate handles the core interception; thin wrappers adapt to
  framework-specific plugin APIs (Fastify plugins, Express middleware, Elysia
  lifecycle hooks).

- **net/http** in Go is the universal substrate. Gin, Echo, Fiber, and chi all
  build on or wrap `http.Handler`. One `http.Handler` middleware covers them all.

## 3. The Best Current Control Surface: OpenAPI/JSON Schema

Any HTTP API with an OpenAPI spec can be brought under baseline Chio governance.

### Auto-Discovery Pipeline

```
OpenAPI spec (YAML/JSON)
    |
    v
chio-openapi: parse routes, methods, params, response schemas, tags
    |
    v
Generate Chio ToolManifest:
    - Each route becomes a candidate ToolDefinition
    - Path params become input_schema fields
    - HTTP method provides a default side-effect hint, not the final truth
    - Tags help seed capability scopes and grouping
    - Explicit curation can suppress, merge, or relabel routes
    |
    v
Generate default policy:
    - deny-by-default for side effects unless declared safe
    - read endpoints get automatic allow with session binding
    - write endpoints require explicit capability grant
    |
    v
Developer overrides (optional):
    - annotations, decorators, or chio.yaml sections
    - only needed for exceptional cases
```

### Chio Metadata Extensions for OpenAPI

Developers add extra Chio metadata only where needed. These extend the OpenAPI
spec via `x-chio-*` fields or standalone `chio.yaml` policy:

```yaml
# In OpenAPI spec (x-chio extensions)
paths:
  /api/patients/{id}:
    get:
      x-chio-sensitivity: high
      x-chio-data-classification: phi
    delete:
      x-chio-side-effects: true
      x-chio-approval-required: true
      x-chio-cost-class: destructive
      x-chio-publish: false

  /api/deploy:
    post:
      x-chio-approval-required: true
      x-chio-budget-limit: { calls: 10, cost_usd: 500 }
      x-chio-egress-policy: internal-only
      x-chio-data-volume-limit: 50mb
```

Or equivalently in `chio.yaml`:

```yaml
routes:
  "DELETE /api/patients/{id}":
    approval_required: true
    cost_class: destructive
    publish: false

  "POST /api/deploy":
    approval_required: true
    budget: { calls: 10, cost_usd: 500 }
    egress: internal-only
```

### OpenAPI Caveats

OpenAPI is the strongest current wedge for HTTP/API governance. It is not
ground truth for all runtime behavior.

- specs can be stale, incomplete, or absent
- interface shape does not fully describe hidden side effects
- not every route should become an agent tool 1:1
- curation and override fields are first-class, not edge cases
- non-HTTP surfaces still require protocol adapters or native integrations

API-security platforms already show that spec-first governance can work in
production. Chio's differentiator would be capability-bound session control and
signed receipts, not the mere fact of reading an OpenAPI file.

## 4. Progressive Adoption Ladder

Chio adoption should not require rewriting an application. Four levels,
each adding depth without breaking the previous level.

### Level 0: Reverse Proxy / Sidecar (Zero Code)

Current shipped CLI surface:

```bash
chio api protect --upstream http://localhost:8000 --spec openapi.yaml
```

What this does:
- Reads the OpenAPI spec
- Generates a default Chio manifest and policy
- Starts a reverse proxy on the configured listen address
- Every request gets: session binding, capability check, receipt signing
- Safe routes (GET/HEAD/OPTIONS) are allowed with session-scoped audit receipts
- Side-effect routes (POST/PUT/PATCH/DELETE) are denied by default without a
  valid capability token
- Raw request bytes are hashed before evaluation, and receipts can be persisted
  durably when `--receipt-store` is configured

**Friction**: zero code changes. Deploy as a sidecar in K8s or a local proxy.

**Limitations**: best for coarse policy and fast rollout. Framework-native
identity normalization, route semantics, and rich session context remain weaker
than substrate middleware because the proxy only sees normalized HTTP traffic.

### Level 1: Framework Middleware (One Import)

Current shipped package examples:

Python (FastAPI):
```python
from chio_fastapi import ChioMiddleware

app = FastAPI()
app.add_middleware(ChioMiddleware, config="chio.yaml")
```

TypeScript (Elysia):
```typescript
import { chio } from '@chio-protocol/elysia'

const app = new Elysia()
  .use(chio({ config: 'chio.yaml' }))
```

Go (net/http):
```go
import chio "github.com/backbay-labs/chio/sdks/go/chio-go-http"

mux := http.NewServeMux()
handler := chio.Protect(mux, chio.ConfigFile("chio.yaml"))
```

What this adds over Level 0:
- Route-aware identity extraction (JWT, session cookie, API key)
- Per-route capability scoping
- Request/response body inspection for guard evaluation
- Framework-native error responses
- Receipts include authenticated caller identity

### Level 2: Annotations / Decorators (Opt-In Precision)

Proposed decorator / plugin APIs:

Python:
```python
from chio_fastapi import chio_requires, chio_approval, chio_budget

@app.delete("/api/patients/{id}")
@chio_requires(scope="patients:delete", sensitivity="high")
@chio_approval(reason="destructive operation on PHI")
async def delete_patient(id: str):
    ...

@app.post("/api/deploy")
@chio_budget(calls=10, cost_usd=500, ttl_secs=3600)
async def deploy(target: str):
    ...
```

TypeScript:
```typescript
app.delete('/api/patients/:id', {
  chio: { scope: 'patients:delete', approval: true, sensitivity: 'high' }
}, handler)
```

What this adds over Level 1:
- Per-route capability scopes declared in code
- Approval workflows for destructive actions
- Budget enforcement per route
- Data classification tags for guard evaluation
- Egress policy per route

### Level 3: Native Protocol Adapters

For agent-specific protocol surfaces:

- **MCP**: `chio-mcp-adapter` (existing) -- wraps MCP servers on qualified tool-call paths
- **A2A**: `chio-a2a-adapter` (existing) -- wraps A2A agents
- **ACP**: `chio-acp-proxy` (existing) -- proxies ACP sessions
- **OpenAI tool_use**: deferred caller-executed function-tool mediation, no
  present-tense OpenAI adapter package claim
- **LangChain**: `chio-langchain` (proposed) -- wraps LangChain Tool interface
- **AG-UI**: `chio-ag-ui-proxy` (proposed) -- secures agent-to-user event streams

These are the deepest integrations where Chio owns a protocol control point.
Pre-effect mediation, trace-only observation, and advisory-only data must be
named per adapter surface rather than implied by the protocol name.

## 5. Shared Core: `chio-http-core`

All substrate adapters share a common request/session/receipt model.

### Normalized Request Model

```rust
/// Protocol-agnostic representation of an HTTP request
/// that Chio needs to evaluate.
pub struct ChioHttpRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// HTTP method.
    pub method: HttpMethod,
    /// Normalized path (template, not instance).
    pub route_pattern: String,
    /// Actual path with parameters resolved.
    pub path: String,
    /// Path parameters extracted by the framework.
    pub path_params: HashMap<String, String>,
    /// Query parameters.
    pub query_params: HashMap<String, String>,
    /// Request headers (sensitive values redacted in receipts).
    pub headers: HashMap<String, String>,
    /// Authenticated caller identity (extracted by substrate).
    pub caller_identity: Option<CallerIdentity>,
    /// Session context (extracted by substrate).
    pub session: Option<SessionContext>,
    /// Content-Type of request body.
    pub content_type: Option<String>,
    /// Request body hash (for receipt binding, not the full body).
    pub body_hash: Option<String>,
}

pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

pub struct CallerIdentity {
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub auth_method: AuthMethod,
    pub token_claims: HashMap<String, serde_json::Value>,
}

pub enum AuthMethod {
    Bearer,
    ApiKey,
    Session,
    Mtls,
    None,
}
```

### Session Model

```rust
pub struct SessionContext {
    pub session_id: String,
    pub started_at: u64,
    pub capability_token: Option<CapabilityToken>,
    pub cumulative_calls: u64,
    pub cumulative_cost_units: u64,
    pub cumulative_bytes: u64,
}
```

### Receipt Model

Every request produces a receipt, regardless of outcome:

```rust
pub struct HttpReceipt {
    pub request_id: String,
    pub route_pattern: String,
    pub method: HttpMethod,
    pub caller_identity_hash: Option<String>,
    pub session_id: Option<String>,
    pub verdict: Verdict,
    pub guard_evidence: Vec<GuardEvidence>,
    pub response_status: u16,
    pub timestamp: u64,
    pub content_hash: String,
    pub signature: Signature,
}
```

## 6. Secure Defaults (Built In, Not Documented Later)

Every substrate adapter ships with these defaults. They cannot be accidentally
disabled.

| Default | Behavior |
|---------|----------|
| **Ephemeral capabilities** | Per-session capability tokens, not static app secrets |
| **Route-scoped credentials** | Capabilities are scoped to specific routes, not the entire API |
| **Signed receipts** | Every allow/deny/cancel/incomplete produces a signed receipt |
| **Request binding** | Receipts bind to session, objective, and approval context |
| **Deny side effects** | POST/PUT/DELETE denied by default unless declared safe |
| **Budget enforcement** | Calls, bytes, cost, and time budgets enforced per session |
| **Approval hooks** | Destructive or high-risk actions require explicit approval |
| **Degraded state handling** | When evidence is incomplete, deny with clear error, never silently pass |

### Guard Classes on HTTP/API Surfaces

Not every "guard" belongs in the same operational bucket.

- **Request / response guards:** deterministic checks on a single request or
  response, such as SSRF controls, schema gating, or output sanitization
- **Session-aware deterministic guards:** deterministic checks that require a
  session journal, such as delegation depth, data-flow limits, or capability
  rotation velocity
- **Signed advisory signals:** behavioral or anomaly observations that should
  start as alerts or escalation inputs, not default hard blocks

The first two classes can fail closed. The third should usually begin as
signed evidence and operator escalation until the signal quality is proven.

## 7. Developer UX: "One Line to Start, Optional Depth Later"

### First Touch (30 seconds)

Proposed CLI / package names:

```bash
# Protect any API with an OpenAPI spec
chio api protect --upstream http://localhost:8000

# Or add one line of middleware
pip install chio-fastapi
# Then: app.add_middleware(ChioMiddleware)
```

### Auto-Discovery

- `chio api protect` reads the OpenAPI spec from `/openapi.json`, `/docs`,
  or a file path
- Generates a default manifest and policy automatically
- Developer only annotates the exceptional cases

### Local Development

- SQLite receipt store (no external dependencies)
- Dev signing keys (auto-generated, clearly marked non-production)
- Human-readable receipt log to stdout
- `chio receipt list --limit 20` for receipt inspection

### Production Swap

- Swap SQLite for hosted receipt store (Postgres, S3, etc.)
- Swap dev keys for HSM-backed signing
- Swap local policy for control plane-managed policy
- **No application code changes required**

## 8. Build Order

The current Rust kernel is an asset. A Rust-only packaging story is an
adoption risk. The sidecar and the first three substrate families are what make
the kernel reachable for most developers.

### Phase 1: Core + Zero-Code Wedge [Shipped]

| Package | Purpose | Crate / CLI |
|---------|---------|-------------|
| `chio-http-core` | Normalized request/session/receipt model | `crates/chio-http-core` |
| `chio-openapi` | Import/generate manifests from OpenAPI specs | `crates/chio-openapi` |
| `chio api protect` | Reverse-proxy / sidecar entrypoint for any HTTP API | `crates/chio-cli` (`chio-api-protect` subcommand) |

### Phase 2: First Substrates (Python, TypeScript, Go) [Shipped]

| Package | Language | Covers | Package Name |
|---------|----------|--------|--------------|
| `chio-sdk-python` / `chio-asgi` | Python | FastAPI, Starlette, Litestar | `sdks/python/chio-sdk-python`, `sdks/python/chio-asgi` |
| `@chio-protocol/node-http` | JS/TS/Bun | Fastify, Express, Hono, Elysia | `sdks/typescript/packages/node-http` |
| `chio-go-http` | Go | net/http, Gin, Echo, Fiber, chi | `sdks/go/chio-go-http` |

### Phase 3: Framework Wrappers (Thin) [Shipped]

| Package | Wraps | Substrate | Package Name |
|---------|-------|-----------|--------------|
| `chio-fastapi` | FastAPI decorator/middleware | `chio-asgi` | `sdks/python/chio-fastapi` |
| `chio-django` | Django/DRF middleware | WSGI-specific | `sdks/python/chio-django` |
| `@chio-protocol/express` | Express middleware | `@chio-protocol/node-http` | `sdks/typescript/packages/express` |
| `@chio-protocol/fastify` | Fastify plugin | `@chio-protocol/node-http` | `sdks/typescript/packages/fastify` |
| `@chio-protocol/elysia` | Elysia lifecycle plugin | `@chio-protocol/node-http` | `sdks/typescript/packages/elysia` |

### Phase 4: Session Journal + Stateful Guards [Shipped]

| Package / Surface | Purpose | Package Name |
|-------------------|---------|--------------|
| `chio-http-session` | Multi-step journal for session-aware deterministic guards | `crates/chio-http-session` |
| session-aware guard suite (internal milestone v3.4) | All session-aware deterministic guards (delegation depth, data-flow limits, rotation velocity) | `crates/chio-guards` |
| signed advisory observations | Emit non-blocking behavioral/risk evidence before default hard-blocking | integrated into guard pipeline |

### Phase 5: Remaining Substrates [Shipped]

| Package | Language | Covers | Package Name |
|---------|----------|--------|--------------|
| `chio-tower` | Rust | Axum and replayable Tower body types; current gRPC coverage is the generic Tower/HTTP2 path rather than a dedicated `tonic::body::Body` qualification | `crates/chio-tower` |
| `chio-spring-boot` | Java/Kotlin | Spring Boot auto-configuration, ChioFilter servlet filter | `sdks/jvm/chio-spring-boot` |
| `ChioMiddleware` | C# | ASP.NET Core middleware | `sdks/dotnet/ChioMiddleware` |

### Phase 6: Protocol Adapters and Deep Integrations (Level 3) [Mixed]

| Package | Protocol | Package Name | Status |
|---------|----------|--------------|--------|
| OpenAI caller-executed function tools | OpenAI function calling interception | TBD | Deferred until receipt/read-boundary gates and adapter qualification land |
| `chio-openapi-mcp-bridge` | OpenAPI-to-MCP bridging with Chio governance | `crates/chio-openapi-mcp-bridge` | Shipped |
| `chio-a2a-edge` | A2A bidirectional bridging | `crates/chio-a2a-edge` | Shipped |
| `chio-acp-edge` | ACP bidirectional bridging | `crates/chio-acp-edge` | Shipped |

## 9. Important Constraint

"Perfectly low friction and secure" is not realistic as a single mode. The
real answer is four modes with one shared kernel:

- **Zero-code path** (reverse proxy) for fast adoption
- **Middleware path** (one import) for real coverage
- **Annotation path** (decorators/config) for least-privilege precision
- **Protocol adapter path** (MCP/A2A/ACP and future qualified OpenAI caller-executed tools) for agent-native surfaces

All four modes share the same kernel, the same receipt format, the same
capability tokens, and the same guard pipeline. The difference is depth of
context available for policy evaluation.

## 10. How This Relates to Existing Protocol Adapters

The existing MCP, A2A, and ACP adapters are **Level 3** in this framework.
They are the deepest Chio-owned protocol integrations, but the mediated,
trace-only, and advisory boundaries still depend on the specific adapter
surface.

The HTTP substrate adapters are **Level 1-2**. They provide the same security
primitives (capabilities, guards, receipts) but operate at the HTTP layer
rather than the protocol layer.

Both levels feed into the same kernel. A single deployment can run:
- An MCP adapter securing qualified MCP tool calls
- An ASGI middleware securing a FastAPI backend
- A reverse proxy securing a legacy Go service

All three produce signed receipts into the same receipt store, evaluated by
the same guard pipeline, governed by the same capability authority.

This is the path that makes Chio a universal security kernel, not just an MCP
gateway.
