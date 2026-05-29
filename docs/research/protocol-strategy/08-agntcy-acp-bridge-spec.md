# AGNTCY ACP Bridge: Engineering Specification

> **SUPERSEDED:** AGNTCY ACP was archived on 2026-04-11. The `agntcy/acp-spec` repo is read-only; ACP was absorbed into A2A. The "frozen v0.2.3" framing in this doc was wrong (frozen meant archived). The proposed `chio-bridge-agntcy` crate is **not** being built. Only the `chio-directory` consume-only integration survives, redirected to AGNTCY Directory + Identity (which remain actively developed) per Webex's production pattern. See [17-agntcy-revisited.md](17-agntcy-revisited.md) for the replacement plan. This doc is retained as historical context; do not implement the bridge spec.

Status: ~~draft, May 2026~~ SUPERSEDED. Successor (concrete) to doc 02 section 2
("AGNTCY (SLIM, OASF, ACP)"). Companion to doc 00's three-ACPs warning.

## TL;DR

AGNTCY's Agent Connect Protocol is REST/OpenAPI 3.1.1, frozen at v0.2.3
in the archived `agntcy/acp-spec` repository, with agent-as-tool
primitives (`Agent`, `Run`, optional `Thread`). Bridge it as
`chio-bridge-agntcy` (NOT `chio-acp-*`: those slots already hold Zed
Agent Client Protocol at `crates/chio-acp-edge` and
`crates/chio-acp-proxy`). Map ACP `Run` to
`ToolServerConnection::invoke` via the `/runs/wait` endpoint,
`/runs/stream` to `invoke_stream`, interrupts surface inline. Inherit
identity from the HTTP substrate because ACP declares no
`securitySchemes`. Introduce `DirectoryProvider` in a new
`chio-directory` crate: strictly read-only, feeds bridge wire-up, never
the hot path or capability scope. MVP is HTTP-only, one ACP server per
connection, two or three hand-allowlisted agents.

## 1. Spec Source and Version

- OpenAPI document:
  [github.com/agntcy/acp-spec/blob/main/openapi.json](https://github.com/agntcy/acp-spec/blob/main/openapi.json),
  rendered at [spec.acp.agntcy.org](https://spec.acp.agntcy.org/).
- Version: `info.version = "0.2.3"`, `openapi = "3.1.1"`.
- Status: archived 2026-04-11. Frozen; AGNTCY's work continues under
  Linux Foundation AComp following the July 2025 donation, no announced
  v1 successor as of May 2026
  ([Zylos protocol survey](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence),
  [4sysops comparison](https://4sysops.com/archives/comparing-ai-protocols-mcp-a2a-agp-agntcy-ibm-acp-zed-acp/)).
  A frozen spec is a feature for a bridge: the wire surface will not
  move under us.
- Reference SDK (Python, informational only):
  [github.com/agntcy/acp-sdk](https://github.com/agntcy/acp-sdk). We
  generate or hand-write a Rust client from the OpenAPI.

## 2. Wire-Level Mapping

ACP has thirty operations across `Agents`, `Threads`, `Thread Runs`,
`Stateless Runs`. The bridge consumes a stable subset.

### 2.1 Discovery: `tool_names()`

Two-step in ACP: `POST /agents/search` returns `Agent[]` with
`agent_id` (UUID) and `metadata`; `GET /agents/{agent_id}/descriptor`
returns `AgentACPDescriptor` with `spec.input/output/interrupts/capabilities`.

`ToolServerConnection::tool_names()`
(`crates/chio-kernel/src/runtime.rs:260`) is synchronous. The bridge
builds an in-memory map at construction time from an operator
allowlist, exposing each agent under its **metadata name slug**
(kebab-case, deduped), not the UUID, to keep capability scopes
human-readable. Side map `tool_name -> agent_uuid` routes invocations.

`/agents/search` is never called on the hot path. Discovery is
operator-curated; refresh is via explicit reload. Section 5's
`DirectoryProvider` is a parallel concept (a directory of ACP
**servers**, each hosting multiple agents).

### 2.2 Invocation: `invoke()`

ACP offers three shapes per run-class:

| Shape      | Stateless                | Stateful                                  |
|------------|--------------------------|-------------------------------------------|
| Async      | `POST /runs`             | `POST /threads/{tid}/runs`                |
| Block/wait | `POST /runs/wait`        | `POST /threads/{tid}/runs/wait`           |
| Stream     | `POST /runs/stream`      | `POST /threads/{tid}/runs/stream`         |

The bridge uses **`POST /runs/wait`** as the default. Request body is
`RunCreateStateless` (`agent_id`, `input`, optional `config`,
`metadata`, `webhook`, `stream_mode`, `on_completion`).

Argument transformation: Chio's `invoke(tool_name, arguments)` wraps as:

```jsonc
{
  "agent_id": "<resolved-uuid>",
  "input": <arguments verbatim>,
  "on_completion": "delete",   // we never want server-side thread garbage
  "metadata": { "chio_request_id": "<RequestId>", "chio_capability_id": "<CapabilityId>" }
}
```

The ACP server responds with a `Run` carrying terminal `status`
(`success` | `error` | `timeout` | `interrupted`) and a `RunOutput`
(oneOf `RunResult` | `RunInterrupt` | `RunError`, discriminated by
`type`). The bridge:

- `success` + `RunResult.values` -> return `Ok(values)`.
- `error` + `RunError.errcode/description` -> map per section 5.
- `timeout` -> `KernelError` transient (retry-eligible).
- `interrupted` -> see 2.4 (events).

Webhook field is set to `None` in MVP; we do not host a public
callback. Threads are not used by `invoke` (`on_completion: delete`).

### 2.3 Streaming: `invoke_stream()`

ACP streaming uses SSE on `POST /runs/stream` (or
`GET /runs/{run_id}/stream`). `stream_mode` is `values` (full snapshot
per chunk) or `custom` (agent-defined). The bridge advertises
`invoke_stream` only when the agent's `AgentACPDescriptor` declares
`capabilities.streaming = true`; otherwise it returns `Ok(None)` from
the override and the kernel falls back to `invoke()`.

Each SSE event maps to one `ToolCallChunk` in
`ToolServerStreamResult::Complete(ToolCallStream { chunks })`
(`crates/chio-kernel/src/runtime.rs:117,136`). Terminal SSE event
(`type: result` or `type: error`) closes the stream; an
`Incomplete { reason }` is emitted if the SSE connection drops before
terminal frame (`reason = "sse-disconnect"`).

### 2.4 Events / Interrupts: `drain_events()`

ACP's `interrupted` run status is the closest analog to MCP's
elicitation: the agent has paused waiting on caller input via the
`RunInterrupt.interrupt` payload (typed against
`AgentACPDescriptor.spec.interrupts`). The bridge surfaces interrupts
**inline** in the invoke return (as a structured error,
`KernelError::ToolInterrupted { interrupt_id, payload }`, a new variant
the bridge would introduce in coordination with the kernel team). It
does NOT use `drain_events` for interrupts, because interrupts are
synchronous with a specific `run_id` and resumption requires the
`POST /threads/{tid}/runs/{run_id}` ("resume") endpoint.

`drain_events()` (`crates/chio-kernel/src/runtime.rs:306`) returns an
empty vec in MVP. A future revision could surface `ToolsListChanged`
when `/agents/search` results diverge from the cached snapshot, but
this requires operator opt-in (auto-importing tools widens trust).

### 2.5 Operations Explicitly Out of Scope (MVP)

Threads (`/threads/*`), background runs without `wait`, run search,
copy, history, delete, cancel. Threads are a stateful ACP concept that
collides with Chio's per-request mediation model. Cancel is reachable
in a future revision if the bridge starts honoring tokio cancellation
tokens from the kernel.

## 3. Identity Mapping

The ACP OpenAPI document declares `components.securitySchemes = {}` and
no global `security` block. ACP defers authentication to the deployer.
This is consistent with the AGNTCY pattern of pairing ACP with a
separate Identity Service that issues verifiable credentials and
expects them to be carried in standard HTTP headers.

The bridge therefore inherits the HTTP substrate's auth and constructs
`CallerIdentity` (`crates/chio-http-core/src/identity.rs:44`) per the
operator-configured scheme. Three supported modes for MVP:

1. **Bearer** (default). Operator hands the bridge a static token (or
   a token source: file path, env var, or a `dyn TokenProvider`). The
   bridge sets `Authorization: Bearer <token>` and records the
   identity as `AuthMethod::Bearer { token_hash: sha256(token) }`.
2. **mTLS**. `reqwest` client built with a client cert + key from
   operator config. Records `AuthMethod::MtlsCertificate { subject_dn,
   fingerprint }` where `subject_dn` and `fingerprint` come from the
   loaded cert via `rustls::pki_types`.
3. **API key**. `X-API-Key: <key>` header, recorded as
   `AuthMethod::ApiKey { key_name: "X-API-Key", key_hash: sha256(key) }`.

`CallerIdentity.subject` is set to the AGNTCY agent metadata's
canonical identifier when the descriptor includes one; otherwise to
`did:web:<host>` derived from the ACP server URL. `verified = true`
only when (a) mTLS bound the connection, or (b) bearer was a JWT and
the kernel's existing JWT verifier accepted it (out of scope for v1).

`CallerIdentity.agent_id` is set to the ACP `agent_id` (UUID) for
provenance. `tenant` is left to the operator.

**Canonical AGNTCY peer ID -> Chio caller subject rule:**

> Subject = `did:web:<acp-host>:<port?>:agents:<agent-id-uuid>` when no
> AGNTCY identity credential is bound. Subject = the VC's `sub` claim
> (typically itself a `did:web` or `did:key`) when AGNTCY's Identity
> Service issued a credential and the kernel verifies it. The bridge
> never invents a `did:chio` for an upstream peer: `did:chio` is
> reserved for principals the local kernel attests.

## 4. Error Model

ACP error sources:

- HTTP transport errors (connection refused, TLS failure, timeout).
- HTTP status codes returned by the ACP server: 404 (not found), 409
  (conflict), 422 (validation), 5xx (server error). The body for these
  is `ErrorResponse` which the spec defines as a bare `string`. The
  bridge stores the raw string as evidence but does not parse it.
- `RunStatus = error` with structured `RunError { errcode: int,
  description: string }`. The `errcode` is agent-defined (the ACP spec
  does not enumerate codes), so the bridge treats it as opaque
  metadata.
- `RunStatus = timeout` (terminal, retryable depending on idempotency).
- `RunStatus = interrupted` (not an error in ACP semantics: the agent
  is waiting on caller input).

Mapping to `KernelError` (defined at
`crates/chio-kernel/src/kernel/mod.rs:473`):

| ACP failure                                      | Chio mapping                                                           | Retry  |
|--------------------------------------------------|------------------------------------------------------------------------|--------|
| Transport: connect/TLS/io                        | `KernelError::ToolServer(transient: true)` (new variant or wrap)       | yes    |
| HTTP 5xx                                         | `KernelError::ToolServer(transient: true)`                             | yes    |
| HTTP 408, 504, `RunStatus=timeout`               | `KernelError::ToolServer(transient: true, reason: "timeout")`          | yes    |
| HTTP 429                                         | `KernelError::ToolServer(transient: true)` with retry-after            | yes    |
| HTTP 401, 403                                    | `KernelError::UntrustedIssuer`-adjacent or new `ToolServerUnauthorized`| no     |
| HTTP 404 on `agent_id`                           | `KernelError::OutOfScope { tool, server }`                             | no     |
| HTTP 422 (validation)                            | `KernelError::InvalidConstraint(<acp-msg>)`                            | no     |
| `RunError { errcode, description }`              | `KernelError::ToolServer(transient: false, code: errcode, msg)`        | no     |
| `RunInterrupt`                                   | `KernelError::ToolInterrupted { interrupt_id, payload }` (new variant) | n/a    |

Retry policy: exponential backoff with jitter, max 3 attempts, only on
`transient: true`. Bridge surfaces a `Retry-After` parsing helper for
429s. Idempotency: the bridge generates a `chio_request_id` UUID in
`metadata` to support server-side idempotency keys if the deployer
adds them later.

## 5. `DirectoryProvider` Trait

Doc 02 introduced the trait sketch. Concrete shape below.

### 5.1 Crate Location

New crate `chio-directory` (alphabetically and semantically distinct
from `chio-federation`, which is heavier-weight: relay peering,
quarantine, observability profiles). `chio-directory` is a leaf crate
with no kernel dependency, depending only on `chio-core-types` for
ID/key types. AGNTCY-specific impls live in `chio-bridge-agntcy`
(reading static lists or AGNTCY's directory HTTP API once it
stabilizes), NANDA impls live in a future `chio-directory-nanda`.

### 5.2 Trait Surface

```rust
// crates/chio-directory/src/lib.rs
use async_trait::async_trait;

#[async_trait]
pub trait DirectoryProvider: Send + Sync {
    /// Stable name for receipts/diagnostics ("agntcy-static", "nanda-https").
    fn name(&self) -> &str;

    /// Resolve a canonical identifier to a record. Closed-world: returns
    /// `Err(DirError::NotAllowlisted)` for identifiers the operator did
    /// not pin. Never makes a network call without operator consent.
    async fn lookup(&self, id: &str) -> Result<DirectoryRecord, DirError>;

    /// Enumerate the full operator-allowlisted set. Used at bridge
    /// wire-up time, never on the hot path.
    async fn allowlisted(&self) -> Result<Vec<DirectoryRecord>, DirError>;

    /// Refresh the cache. Returns the wall-clock of the new snapshot.
    /// Implementations that have no refresh (static config) return
    /// `Ok(self.last_loaded_at)`.
    async fn refresh(&self) -> Result<u64, DirError>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectoryRecord {
    /// Canonical, content-stable identifier. did:web, did:key, did:chio.
    pub canonical_id: String,
    /// Endpoints where the peer can be reached. The bridge picks one.
    pub endpoints: Vec<EndpointHint>,
    /// Advisory capability strings as advertised by the directory.
    /// Structurally separate from CapabilityToken::scope. Never widens
    /// local trust.
    pub advisory_capabilities: Vec<String>,
    /// Verbatim upstream-signed bytes (e.g. AGNTCY VC, NANDA AgentFacts
    /// JWS). Hashed and stored in receipts for provenance.
    pub signed_blob: Vec<u8>,
    /// Identifier of the directory that signed `signed_blob`.
    pub upstream_signer: String,
    /// Wall-clock of when this record was fetched.
    pub fetched_at: u64,
    /// SHA-256 of `signed_blob` for fast comparison in receipts.
    pub blob_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointHint {
    /// "acp", "mcp", "a2a", "https".
    pub protocol: String,
    pub url: String,
    /// Optional transport hint ("https", "mtls", "slim").
    pub transport: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("identifier not in operator allowlist: {0}")]
    NotAllowlisted(String),
    #[error("upstream signature invalid: {0}")]
    BadSignature(String),
    #[error("upstream io: {0}")]
    Io(String),
    #[error("upstream returned malformed record: {0}")]
    Malformed(String),
}
```

### 5.3 Signature Verification

AGNTCY's directory uses verifiable credentials (W3C VC Data Model) for
agent records. The provider verifies the VC's proof at `refresh` time
and rejects records that fail. Verification keys are loaded from the
operator's trust anchor file (a list of issuer DIDs with their public
keys), not auto-resolved. This keeps trust closed-world.

For the AGNTCY-static MVP impl, `signed_blob` is set to the canonical
JSON of the operator's pinned entry and `upstream_signer = "operator"`:
no remote signature to verify, the operator IS the trust anchor.

### 5.4 Refresh / Caching

Default refresh interval: zero (operator must call `refresh()`
explicitly, e.g. via a control-plane reload). An optional
`AutoRefreshDirectoryProvider<P>` decorator can wrap any provider with
a tokio interval. The kernel never triggers refresh as a side effect of
an `invoke()`.

### 5.5 Non-Goal Boundary

**Hard rule, encoded in the trait docs:** `advisory_capabilities` is
purely informational. The bridge MUST NOT pass these strings into
`CapabilityToken::scope` (`crates/chio-core-types/src/capability.rs`),
into Cedar policy, into manifest-driven scope inference, or anywhere
else that affects an authorization decision. They exist for operator
diagnostics ("the upstream peer claims to support these tools") and
for audit comparison ("the receipt shows the peer advertised X but we
issued capability Y"). Clippy lint (custom rule) blocks any conversion
function from `Vec<String>` (advisory) to scope types within
`chio-bridge-agntcy` and `chio-directory`.

## 6. Receipt Fields

`ChioReceiptBody` (`crates/chio-core-types/src/receipt.rs:159`) already
carries `metadata: Option<serde_json::Value>`. The bridge populates a
nested object under `metadata.agntcy_acp`:

```jsonc
{
  "agntcy_acp": {
    "spec_version": "0.2.3",
    "server_url_host": "agent.example.com",         // host only, no path
    "agent_id": "<uuid>",                            // ACP Agent.agent_id
    "agent_name": "research-assistant",              // metadata slug
    "run_id": "<uuid>",                              // server-assigned
    "thread_id": null,                               // MVP is stateless
    "run_status": "success",
    "directory_entry": {                             // present iff resolved via DirectoryProvider
      "provider": "agntcy-static",
      "canonical_id": "did:web:agent.example.com:agents:<uuid>",
      "blob_sha256": "<hex>",
      "upstream_signer": "operator"
    },
    "hop_count": 1                                   // 1 for direct call; >1 if a future relay is in-path
  }
}
```

Rationale: keeping AGNTCY-specific fields under a namespaced sub-object
preserves the byte-stable receipt body for non-AGNTCY callers, and
lets us evolve the AGNTCY block without bumping the receipt schema.
`tool_server` (top-level) is set to the operator-chosen ACP server ID
(e.g. `agntcy:research-corp`), `tool_name` to the agent name slug.
`content_hash` covers the canonical JSON of the input arguments AND
the AGNTCY metadata block (so receipt verification anchors the peer ID
and directory snapshot we trusted at invoke time).

Receipt `trust_level` stays `Mediated` for synchronous bridge calls:
the kernel observed the call inline through `ToolServerConnection`.

## 7. MVP Scope

Smallest shippable bridge (Phase 1 in doc 02's rollout).

**ACP methods implemented:**

- `POST /runs/wait` (synchronous invoke; default).
- `POST /runs/stream` (gated by descriptor capability).
- `GET /agents/{agent_id}/descriptor` (descriptor fetch at startup).
- Nothing else. No threads, no run search, no cancel, no resume.

**Representative ACP agents to validate against:**

1. A research/search agent (string input, `RunResult.values` is a
   structured JSON document; non-streaming).
2. A code-generation agent (string input, streaming `RunResult` with
   incremental chunks; tests `invoke_stream`).
3. A workflow agent that uses `RunInterrupt` for human approval (tests
   the `KernelError::ToolInterrupted` plumbing, even if MVP just
   surfaces a hard error and the caller retries with a new request).

Pick concrete examples from the AGNTCY example agents repo or stand up
two LangGraph reference agents behind ACP for the integration test.

**Config knobs:**

```toml
[bridge.agntcy]
spec_version = "0.2.3"            # pin; warns on mismatch
server_id = "agntcy:research"     # used as tool_server in receipts
endpoint = "https://agent.example.com/acp"
auth = { kind = "bearer", token_file = "/run/secrets/acp-token" }
request_timeout_ms = 30_000
retry_max_attempts = 3
retry_backoff_ms = 250
streaming = true                  # global allow; per-agent gated by descriptor

[[bridge.agntcy.agents]]
agent_id = "11111111-1111-1111-1111-111111111111"
expose_as = "research-assistant"  # becomes Chio tool_name
allow_streaming = true
[[bridge.agntcy.agents]]
agent_id = "22222222-2222-2222-2222-222222222222"
expose_as = "code-gen"
allow_streaming = true

[bridge.agntcy.directory]
provider = "static"               # MVP: in-config; later: agntcy-https
```

The bridge fails closed: invalid config rejects at load time, unknown
agents return `KernelError::OutOfScope` without making an HTTP call.

## 8. Crate Skeleton

### 8.1 Naming

`chio-bridge-agntcy`. **Rejected alternatives:**

- `chio-acp-bridge` / `chio-acp-client`: collides with existing
  `chio-acp-edge` and `chio-acp-proxy`, which implement Zed's Agent
  Client Protocol (verified at
  `crates/chio-acp-edge/src/lib.rs:1-20`). The `chio-acp-*` namespace
  is taken and means a different protocol.
- `chio-agntcy-acp`: works grammatically but breaks Chio's existing
  `chio-bridge-*` prefix convention used by the other tool-server
  bridges. The bridge layer is the most informative grouping, the
  protocol family is the disambiguator.

### 8.2 Cargo.toml

```toml
[package]
name = "chio-bridge-agntcy"
description = "Bridge that exposes AGNTCY Agent Connect Protocol agents as Chio tool servers"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false

[dependencies]
async-trait = { workspace = true }
chio-core = { package = "chio-core-types", path = "../chio-core-types" }
chio-directory = { path = "../chio-directory" }
chio-http-core = { path = "../chio-http-core" }
chio-kernel = { path = "../chio-kernel" }
eventsource-stream = "0.2"        # SSE decoding
reqwest = { workspace = true, features = ["json", "stream", "rustls-tls"] }
rustls = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["macros", "rt"] }
tokio-stream = "0.1"
tracing = { workspace = true }
url = "2"
uuid = { version = "1", features = ["v4", "v7"] }

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

### 8.3 File Layout

```
crates/chio-bridge-agntcy/
  Cargo.toml
  src/
    lib.rs        # crate doc, re-exports, AgntcyAcpBridge entry struct
    client.rs     # ReqwestAcpClient: thin OpenAPI-shaped HTTP client
    config.rs     # AgntcyAcpConfig, AgentBinding
    connection.rs # impl ToolServerConnection for AgntcyAcpBridge
    descriptor.rs # AgentACPDescriptor + capability gating
    directory.rs  # StaticAgntcyDirectoryProvider
    error.rs      # AgntcyAcpError, KernelError mapping
    identity.rs   # AGNTCY peer-ID -> CallerIdentity rule
    receipt.rs    # build the metadata.agntcy_acp block
    sse.rs        # SSE -> ToolCallChunk
  tests/
    integration_invoke.rs
    integration_stream.rs
```

### 8.4 Public API Sketch

```rust
// lib.rs
pub use config::{AgntcyAcpConfig, AgentBinding, AuthConfig};
pub use directory::StaticAgntcyDirectoryProvider;
pub use error::AgntcyAcpError;

pub struct AgntcyAcpBridge { /* opaque */ }

impl AgntcyAcpBridge {
    /// Build the bridge from validated config. Eagerly fetches each
    /// agent's descriptor and rejects on missing/incompatible agents.
    pub async fn new(cfg: AgntcyAcpConfig) -> Result<Self, AgntcyAcpError>;

    /// Reload directory and re-fetch descriptors. Safe to call live.
    pub async fn refresh(&self) -> Result<(), AgntcyAcpError>;
}

#[async_trait::async_trait]
impl chio_kernel::runtime::ToolServerConnection for AgntcyAcpBridge {
    fn server_id(&self) -> &str { /* cfg.server_id */ }
    fn tool_names(&self) -> Vec<String> { /* allowlisted agent slugs */ }

    async fn invoke(&self, tool_name: &str, arguments: serde_json::Value,
                    bridge: Option<&mut dyn chio_kernel::runtime::NestedFlowBridge>)
        -> Result<serde_json::Value, chio_kernel::KernelError>;

    async fn invoke_stream(&self, tool_name: &str, arguments: serde_json::Value,
                           bridge: Option<&mut dyn chio_kernel::runtime::NestedFlowBridge>)
        -> Result<Option<chio_kernel::runtime::ToolServerStreamResult>,
                  chio_kernel::KernelError>;
}
```

A downstream consumer (the kernel host) registers an `AgntcyAcpBridge`
in the tool-server registry exactly like any other
`ToolServerConnection`. No new kernel concept is required.

## 9. Risks and Watch-outs

- **Spec is frozen, but not normative for new AGNTCY work.** The
  acp-spec repo was archived 2026-04-11. We bridge a stable surface,
  but if AGNTCY's LF-AComp track invents an incompatible "ACP v2", we
  will need a second bridge crate (`chio-bridge-acomp`?) rather than
  evolving this one. Treat `spec_version` as a load-time pin to make
  the boundary visible.
- **Empty `securitySchemes`.** ACP punts auth to deployers, so every
  ACP server is a snowflake. The bridge surface intentionally exposes
  multiple `AuthConfig` variants, but operators can still misconfigure
  (e.g. plaintext bearer over HTTP). Bridge MUST refuse non-HTTPS
  endpoints in production builds (allow `http://` only with a debug
  feature flag), and SHOULD warn when bearer is paired with non-mTLS
  on an external endpoint.
- **String-typed `ErrorResponse` and opaque `errcode`.** We cannot
  classify ACP errors precisely. Mapping table in section 5 leans on
  HTTP status codes (well-defined) and treats `RunError` as a
  permanent application error by default. False-positive non-retry on
  a transient agent-side fault is acceptable; false-positive retry on a
  side-effect-causing error is not.
- **Interrupts as a back-channel for unbounded LLM prompts.** A
  malicious ACP agent could return `RunInterrupt` with a payload
  designed to elicit sensitive data from the caller. Bridge MUST size-
  and shape-check `RunInterrupt.interrupt` against the agent's
  declared `spec.interrupts` schema, and reject interrupts whose
  payload type is not in the descriptor.
- **`metadata` field leakage.** ACP's free-form `metadata` round-trips
  through the agent. We use it to thread `chio_request_id`. If the
  agent echoes metadata back into `RunResult.values`, the kernel could
  accidentally re-ingest its own ID. Treat all `RunResult.values` as
  untrusted input.
- **Directory entry vs capability conflation drift.** Easy footgun:
  someone adds a "convenience" helper that turns
  `DirectoryRecord.advisory_capabilities` into capability scope. Encode
  the rule via custom clippy lint and a doc-test that asserts the
  conversion does not exist.
- **AGNTCY-side assumption: identity service stability.** Webex's
  production deployment uses AGNTCY directory and identity components
  for MCP server registration
  ([Webex blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps))
  but ACP is not yet called out as in production there. If AGNTCY
  Identity Service changes its VC format or moves to A2A's VC profile,
  the bridge's identity mapping rule shifts. Section 3 isolates the
  rule in a single function (`map_peer_to_caller_identity`) to
  minimize the blast radius.
- **OASF as alternative discovery.** OASF (OCI-based agent records) is
  the AGNTCY-blessed long-term directory format. MVP uses static
  config; a `chio-directory-oasf` impl is the natural next step. The
  trait shape in section 5 is OASF-ready (`signed_blob` accommodates
  an OASF JWS), but we do not implement OASF reading in v1.
- **SLIM transport not addressed here.** Per doc 02 phasing, SLIM is a
  Phase 3 concern. If an operator wants ACP-over-SLIM before then,
  they can deploy an HTTP-to-SLIM proxy in front of the bridge. The
  bridge does not learn about SLIM.

## Appendix: Citation Map

- ACP OpenAPI document:
  [github.com/agntcy/acp-spec/blob/main/openapi.json](https://github.com/agntcy/acp-spec/blob/main/openapi.json),
  rendered at [spec.acp.agntcy.org](https://spec.acp.agntcy.org/).
- ACP SDK (Python reference): [github.com/agntcy/acp-sdk](https://github.com/agntcy/acp-sdk).
- AGNTCY org and AComp donation context:
  [agntcy.org](https://agntcy.org/),
  [zylos 2026-03-26 protocol survey](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence),
  [4sysops protocol comparison](https://4sysops.com/archives/comparing-ai-protocols-mcp-a2a-agp-agntcy-ibm-acp-zed-acp/).
- Webex production reference:
  [developer.webex.com/blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps).
- Chio code references:
  `crates/chio-kernel/src/runtime.rs:255` (ToolServerConnection),
  `crates/chio-kernel/src/runtime.rs:136` (ToolServerStreamResult),
  `crates/chio-kernel/src/kernel/mod.rs:473` (KernelError),
  `crates/chio-http-core/src/identity.rs:44` (CallerIdentity),
  `crates/chio-core-types/src/receipt.rs:159` (ChioReceiptBody),
  `crates/chio-acp-edge/src/lib.rs:1` (Zed ACP, namespace collision).
