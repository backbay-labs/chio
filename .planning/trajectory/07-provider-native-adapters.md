# Milestone 07: Provider-Native Tool Adapters (OpenAI Responses + Anthropic Tools + Bedrock Converse)

Status: proposed
Lens consensus: integrations + sdk
Owner: integrations track + sdk track
Anchors: `RELEASE_AUDIT`, `BOUNDED_OPERATIONAL_PROFILE`, `QUALIFICATION`, `spec/PROTOCOL.md` (capability semantics, receipt provenance), Milestone 01 (canonical-JSON `ToolInvocation` schema), Milestone 03 (capability algebra and provenance), Milestone 04 (receipt corpus growth), Milestone 10 (tee/replay capture).

## Goal

Bring Chio's mediation surface to where production agent traffic actually lives: the three closed provider tool-call APIs. **Inventory decision**: the existing `crates/chio-openai/` already covers Chat Completions and Responses API extraction (`crates/chio-openai/src/lib.rs:7-11`, `:412-443`); M07 **extends** that crate rather than introducing a parallel `chio-openai-responses-adapter`. The OpenAI deliverable is a `ProviderAdapter` impl, SSE streaming with verdict-at-tool-use-block, and conformance fixtures, all landing on the existing crate behind feature flags. New crates land for the providers that have **zero** prior coverage: `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`, and the shared `chio-tool-call-fabric` that lifts each provider's tool-call into a uniform `ToolInvocation` capability request with provenance. Every adapter must run streaming end to end with verdict-time enforcement at the tool-use block boundary (not per delta) and write a receipt that names the provider and upstream `request_id`.

## Why now

Existing adapters (`chio-mcp-adapter` ~4.4K LOC, `chio-mcp-edge` ~8.6K, `chio-a2a-adapter` ~8.2K, `chio-acp-proxy` ~6.6K) cover the open-protocol corner of the agent ecosystem. Stubs for `chio-ag-ui-proxy`, `chio-openapi-mcp-bridge`, `chio-cross-protocol`, and `chio-hosted-mcp` are placeholders, not production paths. The existing `crates/chio-openai/` crate has batch/helper coverage of OpenAI Chat Completions and Responses extraction, but lacks the M07 fabric trait, SSE streaming with verdict-at-tool-use-block enforcement, and conformance shape; M07 fills those gaps in-place. Anthropic native tool-use and Bedrock Converse have zero adapter coverage anywhere in the workspace and land as new crates. Until those three providers are mediated end to end, Chio's "policy enforced across providers" claim is aspirational. The seven-agent debate ranked this above the M365/Salesforce/Slack bridges precisely because those bridges all sit downstream of provider tool calls; fix the upstream first.

## Adapter shape (shared template)

Each new adapter follows the `chio-mcp-adapter` convention so reviewers see one shape across the workspace.

- `src/lib.rs` re-exports the public surface and declares `pub mod transport;` plus a `pub mod native;` (the native module is the in-process trait surface; `transport` carries the wire codec). Reference: `crates/chio-mcp-adapter/src/lib.rs:33-46`.
- `pub struct <Provider>AdapterConfig { server_id, server_name, server_version, public_key, api_version }` mirrors `McpAdapterConfig` (`crates/chio-mcp-adapter/src/lib.rs:50-62`).
- `pub struct <Provider>Adapter { config, transport: Arc<dyn ProviderTransport> }` mirrors `McpAdapter` (lib.rs:76-80).
- `pub enum <Provider>Error` via `thiserror`, plus a workspace-shared `ProviderError` in `chio-tool-call-fabric` for cross-adapter error taxonomy.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply; no exceptions.
- No em dashes; canonical JSON (RFC 8785) for any signed payload.

## In scope

- `crates/chio-openai/` extension (in-place, behind a `provider-adapter` feature flag for the new surface; existing public API preserved): `responses.create` with `tools=[...]`, `tool_choice`, structured outputs (JSON schema mode), SSE streaming with verdict-at-tool-use-block enforcement, and a `ProviderAdapter` impl. No grep finds in-repo consumers outside the crate itself, so no internal migration PR is required; deprecation of older direct-use APIs (if any) waits one minor release post-M07 close.
- `chio-anthropic-tools-adapter`: `messages.create` with `tools`, `tool_use` and `tool_result` blocks, server tools (`computer_use`, `bash`, `text_editor`) gated behind explicit capability scopes and the documented beta header.
- `chio-bedrock-converse-adapter`: `Converse` and `ConverseStream` with `toolConfig`, multi-account IAM principal mapping into the receipt's `provenance.principal` field.
- `chio-tool-call-fabric`: shared crate exposing `ToolInvocation`, `ProvenanceStamp`, `Principal`, `VerdictResult`, `DenyReason`, `ProviderId`, `ProviderError`, and a `ProviderAdapter` trait. Each per-provider adapter implements `lift(ProviderRequest) -> ToolInvocation` and `lower(VerdictResult, ToolResult) -> ProviderResponse`.
- Conformance harness `chio-provider-conformance` replaying recorded provider traffic from `.ndjson` capture files, asserting verdict equality and receipt-provenance shape.
- Streaming: each adapter mediates the upstream's streaming surface end to end and evaluates verdict at the tool-use block boundary, never per delta.
- Identity: each adapter populates the M03 `provenance` field with provider name, upstream `request_id`, principal (OpenAI org id / Anthropic workspace id / Bedrock IAM ARN), and pinned API version.

## Out of scope

- M365, Salesforce, Slack bridges (cut by Integrations agent under pressure, defer to v5.x).
- Generic webhook-shape adapter (no demand signal yet).
- Vertex AI, Cohere, Mistral tool calls. Documented divergence note in `docs/integrations/providers.md`: Vertex is structurally close to Bedrock but uses Google IAM and separate quota; Cohere and Mistral have smaller surfaces that can ride the fabric trait once it stabilizes. Defer to v5.x.
- Hosted MCP (`chio-hosted-mcp` 13-line shim) is a separate trajectory.
- Replacing or rewriting existing MCP/A2A/ACP adapters; this milestone adds, it does not refactor.

## Pinned upstream API versions

Each adapter pins one upstream version in its `Cargo.toml` and `README.md`. Bumping a pin is a deliberate PR with a fixture re-record.

- **OpenAI Responses**: pin to the GA Responses API. Documented snapshot date 2026-04-25, source `https://platform.openai.com/docs/api-reference/responses`. Streaming event names captured in `fixtures/openai/EVENTS.md`. The Responses API is GA but evolving; pin gates a re-record when event names shift.
- **Anthropic Messages tool-use**: header `anthropic-version: 2023-06-01`. Beta surface (server tools) requires `anthropic-beta: computer-use-2025-01-24` and is gated behind the `computer-use` cargo feature plus an explicit manifest `server_tools` allowlist. Default build does not enable the beta.
- **Bedrock Converse**: pin `aws-sdk-bedrockruntime` to a single workspace version in the root `Cargo.toml`; the adapter uses the `Converse` and `ConverseStream` operations only, with feature surface limited to `tool_config`, `tool_use_block`, and `tool_result_block`. SDK bumps require fixture re-record.

## Streaming versus batch boundary

Every adapter supports both. Verdict latency is bounded by evaluating once per tool-use block, not per delta; deltas are forwarded only after the verdict for the enclosing block resolves.

- **OpenAI**:
  - Batch: `responses.create` (no `stream`). Lift on request, lower verdict into `tool_outputs` on the next turn.
  - Stream: `responses.create` with `stream=true` SSE. Verdict fires at the first `response.output_item.added` event of type `tool_call`; subsequent argument deltas are buffered until verdict resolves, then released.
- **Anthropic**:
  - Batch: `messages.create` (no `stream`). Lift each `tool_use` block on response, lower verdict into a `tool_result` block on the next request.
  - Stream: `messages.create` with `stream=true` event-stream. Verdict fires at `content_block_start` for `tool_use`; `input_json_delta` events are buffered until verdict resolves.
- **Bedrock**:
  - Batch: `Converse`. Lift each `toolUse` block, lower into `toolResult`.
  - Stream: `ConverseStream` over HTTP/2. Verdict fires at the `contentBlockStart` event carrying `toolUse`; subsequent `contentBlockDelta` events are buffered until verdict resolves.

Verdict budget across all three adapters: p99 verdict path completes inside 250ms; merge gate refuses regressions. Heartbeat windows (OpenAI ~30s, Anthropic ~60s, Bedrock per-region) bound the maximum verdict; 250ms is the operational SLO.

## chio-tool-call-fabric trait surface (verbatim)

The fabric is the load-bearing contract. The trait surface below is the exact Rust that lands in `crates/chio-tool-call-fabric/src/lib.rs`. The shape is co-designed with M01 (see M01 "Downstream consumers" entry); M01 emits the schema, the fabric crate consumes generated types via codegen.

Workspace dependency pins (inherited from `Cargo.toml [workspace.dependencies]`, do not re-pin in the crate):

```toml
serde = { workspace = true }      # workspace pin: 1, derive
serde_json = { workspace = true } # workspace pin: 1
tokio = { workspace = true }      # workspace pin: 1, full features
thiserror = { workspace = true }  # workspace pin: 1
```

Crate-local dependencies (pinned in `crates/chio-tool-call-fabric/Cargo.toml`):

```toml
async-trait = "0.1"  # required for `#[async_trait]` on ProviderAdapter
```

Trait surface, verbatim:

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    OpenAi,
    Anthropic,
    Bedrock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    OpenAiOrg { org_id: String },
    AnthropicWorkspace { workspace_id: String },
    BedrockIam {
        caller_arn: String,
        account_id: String,
        assumed_role_session_arn: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceStamp {
    pub provider: ProviderId,
    pub request_id: String,
    pub api_version: String,
    pub principal: Principal,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    pub provider: ProviderId,
    pub tool_name: String,
    /// Canonical-JSON bytes (RFC 8785). Stored as raw bytes so the kernel can
    /// hash without re-serializing.
    pub arguments: Vec<u8>,
    pub provenance: ProvenanceStamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redaction {
    pub path: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    PolicyDeny { rule_id: String },
    GuardDeny { guard_id: String, detail: String },
    CapabilityExpired,
    PrincipalUnknown,
    BudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum VerdictResult {
    Allow { redactions: Vec<Redaction>, receipt_id: ReceiptId },
    Deny { reason: DenyReason, receipt_id: ReceiptId },
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("rate limited by upstream: retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("upstream content policy denied request: {0}")]
    ContentPolicy(String),
    #[error("tool arguments failed schema validation: {0}")]
    BadToolArgs(String),
    #[error("upstream 5xx ({status}): {body}")]
    Upstream5xx { status: u16, body: String },
    #[error("transport timeout after {ms}ms")]
    TransportTimeout { ms: u64 },
    #[error("verdict latency budget exceeded ({observed_ms}ms > {budget_ms}ms); fail-closed")]
    VerdictBudgetExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("malformed upstream payload: {0}")]
    Malformed(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct ProviderRequest(pub Vec<u8>);   // raw upstream payload bytes
pub struct ProviderResponse(pub Vec<u8>);  // raw upstream payload bytes
pub struct ToolResult(pub Vec<u8>);        // canonical-JSON tool output

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderId;
    fn api_version(&self) -> &str;
    async fn lift(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError>;
    async fn lower(
        &self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ProviderResponse, ProviderError>;
}
```

Each adapter maps its native shape into this surface:

- OpenAI `tool_call` (function name + JSON arguments + `call_id`) -> `ToolInvocation { tool_name, arguments, provenance.request_id = call_id }`.
- Anthropic `tool_use` block (`name`, `input`, `id`) -> `ToolInvocation { tool_name = name, arguments = input, provenance.request_id = id }`.
- Bedrock `toolUse` (`name`, `input`, `toolUseId`) -> identical shape; principal additionally carries `caller_arn`, `account_id`, and (when assumed-role) `assumed_role_session_arn`.

Conformance fixtures live at `crates/chio-tool-call-fabric/fixtures/lift_lower/` and exercise round-trip canonical-JSON equality.

### Verdict latency budget (per adapter)

Each adapter enforces a per-tool-call verdict latency budget from `lift` return to verdict resolution. The budget is wall-clock measured inside the adapter and is independent of any upstream heartbeat.

- OpenAI Responses: p99 < 250ms. Window held open by SSE (no heartbeat needed at this scale).
- Anthropic Messages: p99 < 250ms. Window held by `messages.stream` event-stream.
- Bedrock Converse: p99 < 500ms. The looser bound covers cold AWS SDK init plus IMDS / STS round-trips on the first call from a process; steady-state p99 should match the others, but the budget is set to the cold path.

Timeout semantics (fail-closed):

- The adapter starts a timer when `lift` resolves into `Buffering`. If the kernel verdict has not arrived by the budget, the adapter:
  1. Cancels the buffered tool-use forwarding,
  2. Emits a synthetic `Deny { reason: BudgetExceeded, receipt_id: <generated> }` to the kernel for receipt logging,
  3. Closes the upstream stream with `ProviderError::VerdictBudgetExceeded`,
  4. Surfaces a normal denial to the agent (no bypass).
- p99 is enforced in the merge gate (`bench/verdict_latency.rs` per adapter). Regressions block the PR.

### Streaming verdict semantics (state machine)

The adapter buffers upstream stream events at the tool-use boundary and flushes only after the verdict resolves. The state machine, inline:

```text
                  (non-tool delta)
                       ^
                       |
[Buffering] --(tool_use start event seen)--> [ToolUseSeen]
                                                    |
                                                    | call kernel.verdict(invocation)
                                                    v
                                            [AwaitingVerdict]
                                            /                \
                                (Allow)                       (Deny | timeout)
                                  v                                v
                              [Allowed]                        [Denied]
                                  |                                |
                                  | flush buffered deltas          | drop buffered deltas;
                                  | + forward subsequent           | emit synthetic
                                  | tool_use input_json deltas     | tool_result error to agent;
                                  v                                v
                              [Streaming] -- end_block --> [Buffering]   (back to non-tool)
```

State definitions:

- `Buffering`: forwarding non-tool deltas (text, thinking, citations) verbatim to the agent.
- `ToolUseSeen`: a tool-use start event was observed; the adapter has built the canonical `ToolInvocation` and is about to call the kernel.
- `AwaitingVerdict`: kernel call is in flight; argument-delta events are queued, not forwarded. Budget timer is running.
- `Allowed`: kernel returned Allow; queued deltas are flushed; subsequent argument deltas pass through.
- `Denied`: kernel returned Deny or budget expired; queued deltas are dropped; a synthetic `tool_result` carrying the deny reason is injected into the next request, and the upstream stream is terminated.
- `Streaming`: argument deltas pass through until `content_block_stop` (or provider equivalent), at which point the adapter returns to `Buffering` for the next block.

The state machine is implemented in `crates/chio-tool-call-fabric/src/stream.rs` as a single `enum StreamPhase` plus a per-block `BufferedBlock`. Each adapter wraps it; behavior is identical across providers.

### Bedrock IAM principal disambiguation

A single Chio kernel can serve many AWS accounts. The Bedrock adapter resolves the IAM caller (or assumed-role session) into a Chio `Principal::BedrockIam { caller_arn, account_id, assumed_role_session_arn }` before the verdict path runs. To map an IAM ARN onto a Chio principal identity (org/team/owner), the adapter loads:

- `config/iam_principals.toml` at adapter init. Hot-reload is out of scope for v1.

Schema (TOML):

```toml
# config/iam_principals.toml
# Maps IAM ARN patterns to Chio principal owners.
# Order matters: first match wins. Unmatched ARNs deny by default.

default_action = "deny"            # required; only "deny" is accepted in v1
config_version = 1

[[mapping]]
# Exact ARN match, including assumed-role session name.
match = "arn:aws:iam::123456789012:role/ChioAgentRole"
owner = "team-alpha"
notes = "alpha cluster trading agents"

[[mapping]]
# Account-wide rule for production.
match = "arn:aws:iam::987654321098:*"
owner = "team-providence"

[[mapping]]
# Assumed-role session pattern.
match = "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/*"
owner = "team-alpha"
```

Resolution rules:

- The adapter resolves caller identity via STS `GetCallerIdentity` on first request per process (cached for the process lifetime; no per-request STS call).
- An ARN that matches no mapping triggers `Deny { reason: PrincipalUnknown }` and a receipt is signed with the unmapped ARN recorded for audit.
- The mapping file is required; absence at startup is a fatal config error (fail-closed).
- The mapping file is signed with the same Sigstore tooling M09 lands; signature verification gates load.
- Loading code lives in `crates/chio-bedrock-converse-adapter/src/principal.rs`. Tests cover exact match, wildcard match, no-match deny, and missing-file error.

### Conformance harness wiring

- Workflow: `.github/workflows/provider-conformance.yml`. Runs on every PR that touches `crates/chio-{tool-call-fabric,openai-responses-adapter,anthropic-tools-adapter,bedrock-converse-adapter,provider-conformance}/**` or `fixtures/{openai,anthropic,bedrock}/**`.
- Invocation: `cargo test -p chio-provider-conformance --features fixtures-openai,fixtures-anthropic,fixtures-bedrock`. Each feature gates its provider's fixture set so partial builds work.
- Pass criteria:
  1. Every fixture session replays without error against the mock transport.
  2. Each replayed session yields a fabric `ToolInvocation` byte-equal to the captured invocation under canonical JSON.
  3. The kernel verdict matches the captured verdict.
  4. **Verdict equality**: given equivalent canonical request + identical policy, all three providers produce the same verdict. The harness includes a `cross_provider_equality.rs` test that pairs OpenAI/Anthropic/Bedrock fixtures by family and asserts verdict equality after canonical-JSON normalization of the lifted invocation.
  5. The lowered provider response is byte-stable.
- Live-API canary: `.github/workflows/provider-conformance-live.yml` runs nightly, opt-in, against real provider keys; failure opens a diff issue but does not break PR CI.

## Success criteria (measurable)

- Four new crates published locally under `crates/`. Each builds on `cargo build --workspace`, tests pass on `cargo test --workspace`, clippy passes with `unwrap_used = "deny"` and `expect_used = "deny"`.
- End-to-end demo `examples/cross-provider-policy/` shows a single Chio policy file (e.g., "deny `bash` tool when prompt contains PII per `chio-data-guards`") enforced verbatim against all three providers, with three signed receipts that differ only in `provenance.provider`, `provenance.request_id`, and `provenance.principal`.
- Conformance fixture corpus committed under `crates/chio-provider-conformance/fixtures/`: at least 12 recorded sessions per provider (36 total), covering single tool call, parallel tool calls, streaming with mid-stream verdict, structured-output mode, server-tool invocation (Anthropic only, behind feature flag), and a denial path.
- Receipt provenance passes a schema check asserting presence of `provider`, `request_id`, `api_version`, `principal`. Receipts are byte-stable under canonical JSON.
- Pinned API versions documented in each crate's `README.md` (see "Pinned upstream API versions" above).
- M04 receipt corpus grows by at least 36 sessions x N invocations, demonstrating verdict equality across providers. New per-provider fixtures graduate into `tests/replay/fixtures/<adapter_family>/...` via M04's `chio replay --bless` flow (CHIO_BLESS=1 + BLESS_REASON + feature branch + audit-log entry, per M04 "CHIO_BLESS gate logic"); CI never auto-blesses adapter goldens. The `chio-provider-conformance` NDJSON capture format is the exact input that `chio replay --from-tee` consumes, so a captured session can be converted directly into an M04 goldens directory after CODEOWNERS review on `tests/replay/goldens/**`.

## chio-provider-conformance

NDJSON capture format aligned with M10 tee:

```text
{"ts":"...","direction":"upstream_request","provider":"openai","payload":{...}}
{"ts":"...","direction":"upstream_event","provider":"openai","payload":{...}}
{"ts":"...","direction":"kernel_verdict","invocation_id":"...","verdict":"allow|deny","receipt_id":"..."}
{"ts":"...","direction":"upstream_response","provider":"openai","payload":{...}}
```

If M10 ships its tee schema first, conformance reuses it verbatim; otherwise this layout is the provisional contract that M10 absorbs. Replay harness shape: `chio-provider-conformance replay <fixture.ndjson>` reconstructs the upstream request, drives the adapter through a mock transport, and asserts (a) the fabric `ToolInvocation` is byte-equal to the captured invocation, (b) the kernel verdict matches the captured verdict, (c) the lowered provider response matches byte-for-byte under canonical JSON.

Pass criteria: verdict equality across providers when policy and canonical request are equivalent. The cross-provider demo runs the same policy against semantically identical lifted invocations on all three providers and asserts identical verdict and identical receipt body modulo `provenance.*`.

## Phase breakdown

Phase order is OpenAI -> Anthropic -> Bedrock per user direction. Effort sizing convention: S = 1-2 days, M = 3-5 days, L = 6-10 days. Per-task days assume one focused engineer.

### Phase 1 - Tool-call fabric and provenance contract (M, ~5 days)

First commit message: `feat(tool-call-fabric): scaffold ProviderAdapter trait and canonical ToolInvocation shape`.

Atomic tasks:

1. (S, 1d) Add `crates/chio-tool-call-fabric/` to the workspace; land `Cargo.toml`, `src/lib.rs` skeleton, header-stamp markers; deps pinned via `workspace = true` for `serde`, `serde_json`, `tokio`, `thiserror`, plus `async-trait = "0.1"`.
2. (S, 1d) Land the verbatim trait surface (`ProviderId`, `Principal`, `ProvenanceStamp`, `ToolInvocation`, `VerdictResult`, `DenyReason`, `ProviderError`, `ProviderAdapter`). Re-export from `lib.rs`.
3. (S, 1d) Implement the streaming state machine in `src/stream.rs` (`StreamPhase` enum, `BufferedBlock` struct). No provider wired yet; tests cover transitions only.
4. (S, 1d) Wire the fabric into `chio-kernel` via a thin shim: `kernel.verdict_for_provider_invocation(ToolInvocation) -> VerdictResult`. Reuses the existing MCP verdict path; no new policy work.
5. (M, 2d) 8 proptest invariants in `tests/invariants.rs`: (a) `ToolInvocation` round-trips canonical JSON, (b) `ProvenanceStamp` round-trips, (c) `Principal` round-trips for all three variants, (d) lift then lower preserves invocation identity, (e) `VerdictResult::Deny` always carries a `receipt_id`, (f) `ProviderError` Display is em-dash-free, (g) `ProvenanceStamp.received_at` round-trips through canonical JSON without precision loss above ms granularity, (h) schema subsumption against the M01 capability schema (skip if M01 not landed; gate on a feature flag).
6. (NEW) (S, 1d) Land `crates/chio-tool-call-fabric/fixtures/lift_lower/` with 9 minimal canonical-JSON round-trip fixtures (3 per provider) so adapters in later phases have a known-good shape to assert against before recording live sessions.

Exit: fabric crate builds, 8 proptests green, kernel hooked.

### Phase 2 - OpenAI Responses (extend `crates/chio-openai/`) + streaming + conformance skeleton (L, ~9 days)

This phase extends the existing `crates/chio-openai/` crate in-place behind a `provider-adapter` cargo feature; existing public API remains compiled and exported on the default feature set. No `chio-openai-responses-adapter` crate is created.

First commit message: `feat(chio-openai): add ProviderAdapter impl behind provider-adapter feature, pinned to OpenAI Responses 2026-04-25`.

Atomic tasks:

1. (S, 1d) Add `provider-adapter` feature to `crates/chio-openai/Cargo.toml`; depend on `chio-tool-call-fabric` and tighten `reqwest` SSE feature flags. Pin API snapshot date `2026-04-25` in `[package.metadata.chio]` and `README.md`. Existing public surface stays on default features.
2. (M, 2d) In `crates/chio-openai/src/adapter.rs` (new module): implement `ProviderAdapter::lift` for batch `responses.create`: parse `tool_call` items, build `ToolInvocation`, populate `ProvenanceStamp` (`request_id = call_id`, `principal = OpenAiOrg { org_id from header }`, `api_version = "responses.2026-04-25"`). Reuse the existing extraction helpers at `crates/chio-openai/src/lib.rs:412-443` rather than re-implementing them.
3. (M, 2d) Implement `ProviderAdapter::lower` to inject the kernel verdict back into `tool_outputs` on the next turn; deny path emits a synthetic `tool_call_output` with the deny reason.
4. (L, 3d) Streaming: in `crates/chio-openai/src/streaming.rs` (new module), subscribe to SSE; on `response.output_item.added` of type `tool_call`, drive the state machine; buffer subsequent `response.function_call_arguments.delta` events until verdict resolves; flush on Allow, drop on Deny.
5. (S, 1d) Record the 12 OpenAI fixtures (see fixture matrix below) under `crates/chio-provider-conformance/fixtures/openai/`. Each fixture pinned to API snapshot `2026-04-25`.
6. (S, 1d) Land the replay harness skeleton at `crates/chio-provider-conformance/src/{lib.rs,replay.rs,assertions.rs}`. Implements canonical-JSON byte equality and verdict equality assertions.
7. (S, 1d) Bench harness: `crates/chio-openai/benches/verdict_latency.rs`; merge gate refuses regressions over 250ms p99.
8. (S, 0.5d) Deprecation note in `crates/chio-openai/CHANGELOG.md`: any older direct-use APIs that the new `ProviderAdapter` supersedes are marked `#[deprecated(since = "...", note = "use ProviderAdapter; will be removed in 0.X.0")]` but kept compiled for one minor release. Grep at planning time finds no in-repo consumers outside the crate itself, so no internal migration PR is required.

Exit: OpenAI batch and stream paths green via `ProviderAdapter`; 12 fixtures replay; bench within budget; existing `chio-openai` public API still compiles on default features.

#### Phase 2 fixture set (OpenAI Responses, snapshot 2026-04-25)

Grouped by family. Each fixture is one recorded NDJSON session pinned to the API snapshot.

| Family | Fixture id |
|---|---|
| tool_use_basic | `openai_basic_single_tool_call.ndjson` |
| tool_use_basic | `openai_basic_parallel_tool_calls.ndjson` |
| tool_use_basic | `openai_basic_structured_output_json_schema.ndjson` |
| tool_use_with_streaming | `openai_stream_single_tool_call.ndjson` |
| tool_use_with_streaming | `openai_stream_parallel_tool_calls.ndjson` |
| tool_use_with_streaming | `openai_stream_arguments_delta_split.ndjson` |
| tool_use_with_thinking | `openai_thinking_then_tool_call.ndjson` |
| tool_use_with_thinking | `openai_thinking_interleaved_with_tool_call.ndjson` |
| tool_use_with_thinking | `openai_thinking_streaming_with_tool_call.ndjson` |
| tool_use_error_recovery | `openai_error_rate_limited_retry.ndjson` |
| tool_use_error_recovery | `openai_error_content_policy_denial.ndjson` |
| tool_use_error_recovery | `openai_error_kernel_deny_synthetic_tool_output.ndjson` |

### Phase 3 - Anthropic Tools adapter including server tools (L, ~8 days)

First commit message: `feat(anthropic-tools-adapter): scaffold Anthropic tool-use adapter pinned to anthropic-version 2023-06-01`.

Atomic tasks:

1. (S, 1d) Scaffold `crates/chio-anthropic-tools-adapter/`; pin `anthropic-version: 2023-06-01` in `Cargo.toml` metadata and `README.md`. Add `computer-use` cargo feature gating the `anthropic-beta: computer-use-2025-01-24` header.
2. (M, 2d) Implement `lift`/`lower` for batch `messages.create`: parse `tool_use` blocks, build `ToolInvocation`, lower verdict into `tool_result` blocks (Allow forwards the executed tool result; Deny emits a `tool_result` with `is_error: true` and the deny reason).
3. (M, 2d) Streaming: `messages.stream` SSE; verdict fires at `content_block_start` for `tool_use`; `input_json_delta` events buffer until verdict resolves.
4. (M, 2d) Server-tools allowlist: extend `chio-manifest` with a `server_tools: [...]` field; default deny; gate `computer_use`, `bash`, `text_editor` lifts behind the allowlist; document divergence vs Bedrock bash in the crate `README.md`.
5. (S, 1d) Record the 12 Anthropic fixtures (see matrix below). At least 2 are server-tool sessions (gated behind the `computer-use` feature) and 1 is a kernel denial.

#### Phase 3 fixture set (Anthropic Messages, version 2023-06-01)

| Family | Fixture id |
|---|---|
| tool_use_basic | `anthropic_basic_single_tool_use.ndjson` |
| tool_use_basic | `anthropic_basic_parallel_tool_uses.ndjson` |
| tool_use_basic | `anthropic_basic_server_tool_text_editor.ndjson` (computer-use feature) |
| tool_use_with_streaming | `anthropic_stream_single_tool_use.ndjson` |
| tool_use_with_streaming | `anthropic_stream_input_json_delta_split.ndjson` |
| tool_use_with_streaming | `anthropic_stream_server_tool_bash.ndjson` (computer-use feature) |
| tool_use_with_thinking | `anthropic_thinking_then_tool_use.ndjson` |
| tool_use_with_thinking | `anthropic_thinking_streaming_with_tool_use.ndjson` |
| tool_use_with_thinking | `anthropic_thinking_extended_with_tool_use.ndjson` |
| tool_use_error_recovery | `anthropic_error_overloaded_retry.ndjson` |
| tool_use_error_recovery | `anthropic_error_invalid_tool_input.ndjson` |
| tool_use_error_recovery | `anthropic_error_kernel_deny_synthetic_tool_result.ndjson` |

### Phase 4 - Bedrock Converse adapter + cross-provider demo + audit (L, ~10 days)

First commit message: `feat(bedrock-converse-adapter): scaffold Bedrock Converse adapter pinned to single workspace SDK version, us-east-1 only`.

Atomic tasks:

1. (S, 1d) Scaffold `crates/chio-bedrock-converse-adapter/`; pin `aws-sdk-bedrockruntime` to one workspace version in root `Cargo.toml`; restrict to `us-east-1` for v1.
2. (M, 2d) Implement `Converse` (batch) `lift`/`lower` for `toolConfig` and `toolUse`/`toolResult` blocks.
3. (M, 2d) Implement `ConverseStream` (HTTP/2): verdict at `contentBlockStart` for `toolUse`; `contentBlockDelta` events buffered.
4. (M, 2d) IAM principal disambiguation: `crates/chio-bedrock-converse-adapter/src/principal.rs`; load `config/iam_principals.toml`; STS `GetCallerIdentity` once per process; deny-by-default fallback; signed config file gating.
5. (S, 1d) Record the 12 Bedrock fixtures (see matrix below). Bench the cold-init path to validate the 500ms p99 budget.
6. (M, 2d) Cross-provider demo: `examples/cross-provider-policy/`. Single Chio policy file enforced through all three adapters; prints three receipts that differ only on `provenance.*`. Asserts byte-equal verdicts on equivalent canonical inputs.
7. (NEW) (S, 1d) `RELEASE_AUDIT` row referencing the conformance corpus, pinned versions, and the `iam_principals.toml` signing requirement.

#### Phase 4 fixture set (Bedrock Converse, single workspace SDK pin, us-east-1)

| Family | Fixture id |
|---|---|
| tool_use_basic | `bedrock_basic_single_tool_use.ndjson` |
| tool_use_basic | `bedrock_basic_parallel_tool_uses.ndjson` |
| tool_use_basic | `bedrock_basic_assumed_role_principal.ndjson` |
| tool_use_with_streaming | `bedrock_stream_single_tool_use.ndjson` |
| tool_use_with_streaming | `bedrock_stream_content_block_delta_split.ndjson` |
| tool_use_with_streaming | `bedrock_stream_cold_init_path.ndjson` |
| tool_use_with_thinking | `bedrock_thinking_then_tool_use.ndjson` |
| tool_use_with_thinking | `bedrock_thinking_streaming_with_tool_use.ndjson` |
| tool_use_with_thinking | `bedrock_thinking_extended_reasoning_with_tool_use.ndjson` |
| tool_use_error_recovery | `bedrock_error_throttling_retry.ndjson` |
| tool_use_error_recovery | `bedrock_error_principal_unknown_deny.ndjson` |
| tool_use_error_recovery | `bedrock_error_kernel_deny_synthetic_tool_result.ndjson` |

### New M07-scope sub-tasks (Round-2 additions)

- (NEW) **Provenance-stamp signing helper** in `chio-tool-call-fabric`. A small `sign_provenance(stamp, signing_key) -> SignedProvenance` helper plus its inverse. Today the receipt is signed but the provenance stamp itself is not separately attestable; M07 surfaces a stand-alone signed stamp so downstream auditors can verify identity without pulling the whole receipt. Lands in Phase 1 task 6 area.
- (NEW) **Per-provider error-taxonomy table doctest** in each adapter's `README.md`, parsed by a workspace test that asserts every `ProviderError` variant is mapped from at least one native error envelope per provider. Prevents silent taxonomy gaps. Lands in Phases 2-4 alongside each adapter's README.
- (NEW) **Conformance fixture re-record CLI**: `chio-provider-conformance record --provider <p> --scenario <id>` that captures live traffic into the canonical NDJSON shape and writes it to `fixtures/<provider>/`. Today re-record is implicit and informal; this makes it a one-line operation tied to API-pin bumps. Lands as a small follow-up in Phase 4.

## Dependencies

- M01 (canonical-JSON `ToolInvocation` schema): fabric inherits its types if M01 lands first; otherwise fabric defines a provisional shape that M01 ratifies.
- M03 capability algebra defines the provenance semantics each adapter populates and the principal disambiguation rules.
- M04 receipt corpus: each conformance run grows the corpus and feeds release-audit evidence.
- M10 tee/replay infrastructure: shared `.ndjson` capture format. If M10 ships first, conformance reuses it verbatim. Otherwise this milestone defines the provisional format and M10 absorbs it.
- AWS SDK for Rust (`aws-sdk-bedrockruntime`), `reqwest` with SSE support, existing workspace `tokio` and `serde_json`.
- Independent of M02, M05, M06, M08, M09.

## Risks and mitigations

- **Anthropic computer-use beta volatility**: surface evolves between beta header dates and screenshot side-channel semantics shift. Mitigation: gate behind `computer-use` cargo feature plus the manifest `server_tools` allowlist; default build excludes it; CI runs a feature-on lane; bump pin behind a deliberate PR.
- **Bedrock IAM principal disambiguation across multiple AWS accounts**: assumed-role chains can collapse caller and session identities. Mitigation: provenance carries `caller_arn` and `assumed_role_session_arn` separately; never collapse; one Chio kernel can serve many accounts.
- **OpenAI structured-outputs schema evolution**: JSON schema dialect and `response_format` shape iterate. Mitigation: pin one schema dialect in the adapter, record a fixture per schema variant, refuse to silently coerce.
- **Per-provider error taxonomy translation**: each provider's error envelopes (rate-limit, content-policy, tool-loop) are inconsistent. Mitigation: `ProviderError` defines a shared taxonomy (`RateLimited`, `ContentPolicy`, `BadToolArgs`, `Upstream5xx`, `TransportTimeout`); each adapter maps native shapes into it and records the mapping table in its `README.md`.
- **Rate limits during conformance runs**: live providers throttle CI. Mitigation: conformance is fixture-driven; live-API runs gated behind an opt-in nightly job that fails open with a diff issue, not a hard CI break.
- **Streaming verdict latency**: user-visible cost. Mitigation: 250ms p99 verdict budget; benchmark in Phase 2; merge gate refuses regressions.
- **Recorded fixtures drift from live APIs**: nightly canary diffs live response shape against fixtures and opens an issue with the diff attached.
- **Server-tool trust boundary**: `computer_use` is a much larger surface than text tools. Mitigation: default-deny manifest, explicit `server_tools: [...]` allowlist with per-tool capability scope, release-audit note before any non-test fixture exercises it.

## Code touchpoints

- `crates/chio-tool-call-fabric/` (new)
- `crates/chio-openai/` (extended in-place; new `adapter.rs` and `streaming.rs` modules behind `provider-adapter` feature)
- `crates/chio-anthropic-tools-adapter/` (new)
- `crates/chio-bedrock-converse-adapter/` (new)
- `crates/chio-provider-conformance/` (new, plus `fixtures/{openai,anthropic,bedrock}/`)
- `examples/cross-provider-policy/` (new)
- `crates/chio-kernel/src/lib.rs` (small edit: route `ProviderAdapter` invocations through the existing verdict path)
- `crates/chio-manifest/src/lib.rs` (extend manifest schema with `server_tools` allowlist for Anthropic)
- `Cargo.toml` workspace members (add four crates)
- `docs/integrations/providers.md` (new; documents pinned versions, error taxonomy, deferred providers)

## Open questions

- **Which provider lands first?** Recommend OpenAI Responses: largest deployment surface, GA API, cleanest streaming event taxonomy. Anthropic second (server tools surface justifies the wait), Bedrock last (AWS SDK pin is heaviest).
- **Single AWS region first?** Yes. Phase 4 ships against `us-east-1` only; multi-region opens a separate work item once the principal disambiguation contract bakes.
- **Vertex AI / Cohere / Mistral**: explicitly out of scope for v1. Documented in `docs/integrations/providers.md` as deferred-but-tractable once the fabric trait stabilizes; Vertex is structurally close to Bedrock but with Google IAM, Cohere and Mistral are smaller surfaces.
- **Fabric crate location**: separate crate `chio-tool-call-fabric` rather than folding into `chio-core-types`; the lift/lower trait pulls in HTTP and SDK deps that do not belong in core.
- **Replay corpus storage**: in-tree under `fixtures/` for v1 (12 sessions per provider stays well under 1MB each); revisit at v5 if size grows.
- **Bedrock multi-account**: one kernel can serve many accounts; principal disambiguates. Revisit if quotas force per-account separation.
- **Cross-provider demo location**: `examples/cross-provider-policy/` for v1 because it is the audit-evidence artifact; promote to a `chio-cli` subcommand once the surface stabilizes.
