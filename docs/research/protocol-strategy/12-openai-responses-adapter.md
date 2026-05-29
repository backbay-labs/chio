# 12. OpenAI Responses API Adapter (E1)

> **Historical research note (PR 652):** Use [00-overview-v2.md](00-overview-v2.md) and [18-decision-packet.md](18-decision-packet.md) for planning. This file remains research input, not an implementation ticket.
>
> **Erratum (PR 652 review):** `tool_origin` records execution locus, not redaction policy. ADR-0010 keeps `tool_origin` and `redaction_mode` as separate signed current v1 fields. The planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`. References below that imply redaction as an origin variant should be read as historical.
>
> **API refresh note (PR 652 review):** Before implementation, refresh against the current official OpenAI tools docs. `function` tools remain the clean MVP seam because the caller executes them. Current tool docs also describe `computer` as a caller-harness action surface and remote MCP / connectors as approval-mediated but externally executed surfaces, so this document's older "all built-ins are host-executed" shorthand must not drive adapter code.
>
> **Current status:** No present-tense OpenAI adapter package is part of the v1
> protocol claim. The workspace may contain partial, feature-gated OpenAI
> lifting/lowering or stream-gating code, but it is not a qualified adapter and
> does not include a release-ready real HTTP client. OpenAI work remains blocked
> until v1 receipt authority, read-boundary, and adapter qualification gates
> land and official docs are refreshed in the ticket itself.

Status: research; any in-tree OpenAI code is partial and unqualified.
Branch: `research/protocol-strategy-2026`.
Output of swarm task E1. Coordinates with X1 (current v1 receipt-kind semantics) on the
`tool_origin` field and with the latency-audit track on streaming gates.

## TL;DR

OpenAI's `v1/responses` endpoint is the post-Assistants, post-`chat/completions`
path forward for OpenAI fleets. It introduces an agentic loop with internal
iteration, a per-item output stream, and a family of tool surfaces whose
execution locus varies by tool (`function`, hosted tools, remote MCP /
connectors, and caller-harness `computer` actions). Chio cannot treat those as
one boundary, so the adapter must distinguish three
provenance categories on every tool record: caller-executed,
host-executed-provider-reported, and host-executed unmediated. This adds one
normative field to the
receipt schema (`tool_origin`) and a "trace receipt" sub-type that carries no
verdict because there is nothing to mediate. Read that historical shorthand as
ADR-0010's `trace_observation` or `advisory_evaluation` receipt kind, not as a
mediated decision receipt. A future OpenAI adapter crate may gate only
caller-executed `function` tools over streaming SSE; reasoning and built-in
tools remain deferred until a surface-specific boundary ticket proves a
Chio-owned dispatch boundary.

## Wire shape

### Request

`POST /v1/responses` accepts a flattened input plus separate
`instructions`, `tools`, `reasoning`, and conversation-state fields rather
than the `messages` envelope of `chat/completions`
([migrate-to-responses][migrate], [api-reference][apiref]):

- `model` (required, e.g. `gpt-5-2025-08-07` - date-pinned variants are the
  contract surface; bare names alias to the latest).
- `input` - string, or array of input items (`message`, `image`, `file`,
  `function_call_output`, `mcp_tool_call_output`).
- `instructions` - replaces the `system` role; pinned per-call.
- `tools` - array of typed tool entries:
  - `function` (caller-executed, schema like Chat Completions but
    internally tagged and strict by default).
  - Hosted tools such as `web_search`, `file_search`, `code_interpreter`,
    and `image_generation`, plus newer tool families documented by OpenAI.
  - `computer` (caller-harness action surface, not the older preview shape).
  - `mcp` (remote MCP server invoked by OpenAI - host-executed but the
    remote MCP server itself is third-party).
- `reasoning` - `{ effort: "minimal" | "low" | "medium" | "high",
  summary: "auto" | "detailed" | "none" }`. Only for reasoning models
  (o3, o4-mini, gpt-5 reasoning variants).
- `conversation` and `previous_response_id` - turn-chaining handles.
- `store` (default true) - persistent state on OpenAI's side.
- `stream` (default false; MVP forces true).
- `parallel_tool_calls`, `tool_choice`, `max_output_tokens`,
  `temperature`, `top_p`, `metadata`, `safety_identifier`,
  `prompt_cache_key`, `truncation`, `include`, `text.format`
  (structured output, replaces `response_format`).

### Response

The response wraps an `output[]` array of typed items rather than the
`choices[]` envelope. Each item carries a stable `id` and `type`:

- `message` - text, refusal, image, audio, citations.
- `function_call` - caller-executed tool request; carries `call_id`,
  `name`, `arguments`.
- `reasoning` - reasoning step or summary (the full reasoning is
  opaque unless `include: ["reasoning.encrypted_content"]`).
- `web_search_call`, `file_search_call`, `code_interpreter_call`,
  `computer_call`, `image_generation_call`, `mcp_call`,
  `mcp_list_tools` - host-executed tool records with status and
  truncated result data.

Top-level fields: `id`, `object: "response"`, `status` (`in_progress`,
`completed`, `incomplete`, `failed`), `model`, `system_fingerprint`,
`usage` (with `input_tokens`, `output_tokens`, `reasoning_tokens`,
`cached_tokens`), `metadata`, `error`, `incomplete_details`,
`previous_response_id`.

### Streaming events

The SSE protocol emits a typed event per state transition
([streaming-events][stream]; community summary in
[community-stream-events][csguide]):

- Lifecycle: `response.queued`, `response.created`,
  `response.in_progress`, `response.completed`, `response.incomplete`,
  `response.failed`, and out-of-band `error`.
- Items: `response.output_item.added` / `.done`,
  `response.content_part.added` / `.done`.
- Text and refusal: `response.output_text.delta` / `.done`,
  `response.output_text.annotation.added`, `response.refusal.delta` /
  `.done`.
- Reasoning: `response.reasoning_summary_part.added` / `.done`,
  `response.reasoning_summary_text.delta` / `.done`,
  `response.reasoning_text.delta` / `.done`.
- Function calls: `response.function_call_arguments.delta` / `.done`.
- Custom tools: `response.custom_tool_call_input.delta` / `.done`.
- Built-in tools: `response.web_search_call.*`,
  `response.file_search_call.*`, `response.code_interpreter_call.*`
  (plus `.code.delta` / `.code.done`),
  `response.image_generation_call.*` (including
  `partial_image`), `response.computer_call.*`.
- MCP: `response.mcp_call_arguments.delta` / `.done`,
  `response.mcp_call.in_progress` / `.completed` / `.failed`,
  `response.mcp_list_tools.in_progress` / `.completed` / `.failed`.
- Audio: `response.audio.delta` / `.done`, plus transcript events.

### Versioning

OpenAI pins by model id (`gpt-5-2025-08-07`, `gpt-5.5-2025-mm-dd`,
`o4-mini-2025-mm-dd`). The endpoint itself is unversioned but capability
shape varies per model. The adapter records `model` and
`system_fingerprint` on every receipt and refuses unpinned model names in
production profiles (fail-closed: invalid pin rejects at load time, per
house rules).

## Built-in tools categorization

| Tool | Executes where | Chio sees | Tool origin |
|------|----------------|-----------|-------------|
| `function` | Caller | Full args + result | `caller-executed` |
| `web_search` | OpenAI infra | Query text in args; result truncated | `host-executed-provider-reported` |
| `file_search` | OpenAI infra | Query + retrieved file ids | `host-executed-provider-reported` |
| `code_interpreter` | OpenAI sandbox VM | Generated Python source via `.code.delta`, container id | `host-executed-provider-reported` |
| `image_generation` | OpenAI infra | Prompt + image bytes (large) | `host-executed-provider-reported` |
| `computer` | Caller harness, model-orchestrated | Batched actions surfaced to caller for execution | `caller-executed` (actions) plus provider-reported planning trace |
| `mcp` (remote) | OpenAI fetches from third-party MCP | Tool name + args + results | `host-executed-unmediated` (the third-party MCP is fully outside Chio's policy domain) |

Caller-executed means the kernel can run the standard
`ToolServerConnection::invoke` mediation: lift -> verdict -> lower (the
same shape as Anthropic's tool-use blocks today, see
`crates/chio-anthropic-tools-adapter/src/adapter.rs:38-99`).

`host-executed-provider-reported` means Chio records that the request was made
and that OpenAI reported execution, but cannot constrain inputs that are
already gone or outputs that are truncated or binary. If the provider supplies a
verifiable signature in the future, a later ADR can add that as a distinct
origin. Current records use trace/advisory receipt semantics and must not reuse
`Allow`/`Deny`.

`host-executed-unmediated` is the strongest disclaimer: Chio neither
mediated nor received a meaningful attestation of execution semantics
(third-party MCP servers are the canonical example). Receipt carries
`tool_origin = "host-executed-unmediated"` and a flag for downstream
SIEM rules.

Coordinate with X1 on the exact enum:

```rust
#[serde(rename_all = "kebab-case")]
pub enum ToolOrigin {
    CallerExecuted,
    HostExecutedProviderReported { provider_report_ref: String },
    HostExecutedUnmediated,
}
```

This field must be present on every `ToolResult` record in receipt
schema v3; defaulting to `CallerExecuted` would silently mislabel
host-executed traffic, so the field is required (no default).

## Reasoning models

o3, o4-mini, and gpt-5 reasoning variants emit `reasoning` items
alongside their normal output. The adapter:

1. Records a boolean `reasoning_used: bool` and the configured
   `reasoning_effort` on every receipt. SIEMs and step-up policies key
   off this.
2. Applies redaction policy to `response.reasoning_summary_text.*`
   events before forwarding. Reasoning summaries leak intent; treat
   them as PII-class output and run them through the same
   `chio-log-redact` filters used for tool arguments. The full
   `response.reasoning_text.*` channel (when not encrypted) gets
   redacted by default and only released when policy explicitly allows
   the calling agent to see it.
3. Does not by itself change the verdict, but a policy can require
   step-up auth or extra appraisal when `reasoning_effort >= medium`
   (this is consistent with the appraisal trigger surface in
   `chio-appraisal`).

When `include: ["reasoning.encrypted_content"]` is set, Chio forwards
the opaque ciphertext but records a content hash so the next turn can
be checked for replay.

## Agentic loop and the bridge contract

A single `v1/responses` call can internally fire multiple tool calls
(e.g. `web_search` -> `code_interpreter` -> `function`) before
returning. The bridge contract maps each surfaced event to a separate
evaluation:

- Every `response.function_call_arguments.done` event triggers one
  `ToolServerConnection::invoke` evaluation, gated the same way the
  Anthropic adapter gates `content_block_stop` for `tool_use` blocks
  (`crates/chio-anthropic-tools-adapter/src/streaming.rs:1-80`). The
  adapter buffers the `output_item.added` and arguments-delta frames
  until `.done`, then evaluates; deny fails closed before any frame
  for that item is released downstream.
- Every host-executed-provider-reported completion event (e.g.
  `response.web_search_call.completed`) emits a trace/advisory observation
  using ADR-0010 receipt-kind semantics. It must not be modeled as `Allow`,
  because Chio cannot block it retroactively.
- Every `response.mcp_*` event emits a trace observation with
  `tool_origin: host-executed-unmediated` and a flag the downstream
  control-plane can route to a stricter policy lane.
- The terminal `response.completed` event flushes a final aggregate
  record that links all per-event records under a single `response_id` while
  preserving each linked record's `receipt_kind` and `boundary_class`.

The adapter exposes a single `Stream<Item = AdapterEvent>` to the
kernel rather than the per-tool-call coroutine shape. Each event
carries either a `ToolInvocation` (for caller-executed) or a
`ToolTrace` (for host-executed). The kernel decides whether to issue
a verdict or simply log.

## Compare and contrast with `chio-anthropic-tools-adapter`

Reusable from Anthropic
([`crates/chio-anthropic-tools-adapter/src/adapter.rs:30-120`][anth-adapter],
[`crates/chio-anthropic-tools-adapter/src/streaming.rs:29-80`][anth-stream]):

- The `lift` / `evaluate` / `lower` shape composes verbatim for
  `function` tools.
- The SSE buffer-and-gate state machine (buffer until `.done`,
  evaluate, then release) carries over to
  `response.function_call_arguments.delta` / `.done`.
- The fail-closed deny pathway: drop buffered frames, surface
  `tool_result` style cancellation.
- `ProviderId`, `ProvenanceStamp`, `ToolInvocation`, `ToolResult`,
  `VerdictResult` from `chio-tool-call-fabric` are shared.

Structurally different:

- Anthropic Messages returns one tool_use block at a time; the caller
  always dispatches. OpenAI Responses can internally iterate, so the
  adapter is the dispatch loop, not just a translator.
- Anthropic has only three "server tools" (`bash`,
  `text_editor`, `computer_use`) and they each surface to the caller
  for execution (see `SERVER_TOOL_NAMES` in
  `crates/chio-anthropic-tools-adapter/src/adapter.rs:24-28`). OpenAI
  has six host-executed tools that never surface inputs/outputs in
  full.
- Anthropic streaming uses `content_block_start` / `_delta` / `_stop`
  with a single content-block dimension; OpenAI streaming has nested
  output-item / content-part dimensions plus tool-specific event
  families.

Extract: a `LlmToolAdapter` trait into
`chio-provider-adapter-core` (which today is a near-empty crate -
`crates/chio-provider-adapter-core/src/lib.rs`) covering:

```rust
pub trait LlmToolAdapter {
    type Lifted;
    type Verdict;
    type Lowered;
    fn lift(&self, raw: ProviderRequest) -> Result<Self::Lifted, ProviderError>;
    fn evaluate(&self, lifted: &Self::Lifted) -> Result<Self::Verdict, ProviderError>;
    fn lower(&self, lifted: Self::Lifted, verdict: Self::Verdict) -> Result<Self::Lowered, ProviderError>;
    fn classify_tool_origin(&self, tool_name: &str) -> ToolOrigin;
}
```

Plus a `StreamGate` generic over event-type tags so both adapters share
the buffer-then-evaluate state machine and the deny-fails-closed
guarantees.

## Crate structure

Historical crate sketch (name and layout still subject to the adapter ticket):

```
crates/chio-openai-responses-adapter/
  Cargo.toml
  src/
    lib.rs           # AdapterConfig, Adapter handle, ProviderId::OpenAi binding
    transport.rs     # SSE transport, retry, bearer auth header injection
    request.rs       # ResponsesRequest types and builders
    response.rs      # Output item types, status, usage, error
    events.rs        # SSE event enum, frame parser
    builtin_tools.rs # ToolOrigin classifier, attestation construction
    receipt.rs       # Per-event receipt + aggregate response receipt
    streaming.rs     # StreamGate over output_item / content_part / tool calls
```

Do not claim an existing OpenAI adapter surface in this research doc. If
an OpenAI adapter is later implemented, the ticket must define the crate name,
official API pin, fixture corpus, and migration story.

## Authentication

OpenAI uses bearer API keys. The adapter binds an opaque key handle
(not the raw key) to a `CallerIdentity::auth_method =
AuthMethod::ApiKey { key_name: "Authorization", key_hash }` per
`crates/chio-http-core/src/identity.rs:14-20`. The key is stored only
as its SHA-256 hash on the receipt; the live key sits in
`chio-credentials` keyed by tenant + `subject`.

Multi-tenant rotation considerations:

- The OpenAI key may be shared across many `subject` values in a fleet
  setup. Bind `CallerIdentity::subject` (the agent identity) to the
  receipt; bind `key_hash` to the call. A rotation changes
  `key_hash` while `subject` stays stable.
- Record the OpenAI `safety_identifier` and `prompt_cache_key` fields
  on the receipt. Both are sender-controlled per-call identifiers
  that complement Chio's `subject`.
- For OAuth-fronted fleets (where the caller authenticates to Chio via
  OIDC, and Chio holds the OpenAI key), apply a per-call grant scope
  check before the bearer header is attached. Fail closed if the
  caller's grant does not list the OpenAI provider in scope.

## Receipt fields

Per-call (non-streaming) and per-stream-segment receipt extras:

| Field | Source | Notes |
|-------|--------|-------|
| `response_id` | `response.id` | Stable per call. |
| `model` | `response.model` | Date-pinned. |
| `system_fingerprint` | `response.system_fingerprint` | Pin per OpenAI's spec. |
| `usage` | `response.usage` | `input_tokens`, `output_tokens`, `reasoning_tokens`, `cached_tokens`. |
| `previous_response_id` | request | Turn-chain anchor. |
| `tool_origin` | classifier | Required on every tool record. |
| `reasoning_used` | bool | True iff `reasoning` field set or reasoning items in output. |
| `reasoning_effort` | request | Optional. |
| `incomplete_details` | response | Reason if `status = incomplete`. |
| `refused` | bool | True iff any `response.refusal.done` arrived. |
| `safety_identifier` | request | Echoed. |
| `prompt_cache_key` | request | Echoed; affects replay correlation. |
| `input_hash` | computed | SHA-256 of canonical-JSON of `input` + `instructions`. |
| `tool_results_hash` | computed | SHA-256 of canonical-JSON of the ordered list of all `function_call_output` items consumed plus host-executed-provider-reported completion payloads. Hash anchors replay. |

`input_hash` and `tool_results_hash` are the replay-binding fields and
must be canonicalized via `chio_core::canonical::canonical_json_bytes`
(same path the Anthropic adapter uses, see
`crates/chio-anthropic-tools-adapter/src/adapter.rs:79-83`).

## Edge cases

- **Streaming truncation**: connection drops mid-stream. The gate
  flushes any in-flight buffered tool call as deny-by-default and
  emits a receipt with `verdict = DenyTruncated`. The aggregate
  response receipt is marked `partial = true`.
- **Partial responses (`response.incomplete`)**: emit aggregate
  receipt with `status = incomplete`, copy `incomplete_details`. Do
  not retroactively deny already-released frames; subsequent turns
  must surface the truncation to the agent so it does not act on
  partial context.
- **Refusals (`response.refusal.*`)**: the model declined to produce
  content. This is not a Chio-mediated `Allow`; the aggregate record uses a
  non-authorizing refusal outcome, records `refused = true`, and captures the
  refusal text subject to redaction policy.
- **Content-filter triggers**: OpenAI emits
  `response.failed` with `error.type = "content_filter"`. The adapter
  surfaces this as a `ProviderError::ContentFilter` and records a
  non-authorizing provider-content-filter outcome for the aggregate record.
  Any host-executed tool calls that already completed retain their
  trace observations.
- **MCP failures (`response.mcp_call.failed`)**: emit a trace observation
  with `tool_origin = HostExecutedUnmediated` and
  `outcome = Failed`. SIEM rules can key off this combination.
- **`response.queued`**: long queue depth - record as a latency
  annotation on the receipt; not a verdict input.

## MVP scope

First release ships only:

- Caller-executed `function` tools (`tool_origin = CallerExecuted`).
- Streaming SSE only (parity with how the Anthropic adapter gates
  Messages SSE; non-streaming becomes a follow-on convenience).
- Non-reasoning models (gpt-5, gpt-4.1; o3/o4 deferred until reasoning
  redaction policy lands).
- Bearer-API-key auth, single tenant, no fleet rotation.
- No built-in tools; the adapter refuses requests whose `tools` array
  contains any non-`function` entry until the second release.
- Receipt fields: `response_id`, `model`, `system_fingerprint`,
  `usage`, `input_hash`, `tool_results_hash`, `tool_origin`,
  `previous_response_id`.

Follow-on releases add: built-in-tool trace observations, reasoning models
with summary-redaction, remote MCP, fleet-key rotation,
non-streaming path, computer action surface (which has its own threat
model and probably wants its own adapter sub-module).

---

## Summary

1. Future crate name TBD; the potential MVP gates only caller-executed
   `function` tools over streaming SSE on non-reasoning models, refusing any
   request with built-in tools or reasoning configured.
2. The novel receipt field is `tool_origin` (enum:
   `caller-executed` | `host-executed-provider-reported` | `host-executed-unmediated`),
   required on every tool record so host-executed calls cannot
   silently masquerade as mediated.
3. File path: `docs/research/protocol-strategy/12-openai-responses-adapter.md`.

[migrate]: https://developers.openai.com/api/docs/guides/migrate-to-responses
[apiref]: https://platform.openai.com/docs/api-reference/responses
[stream]: https://developers.openai.com/api/reference/resources/responses/streaming-events
[csguide]: https://community.openai.com/t/responses-api-streaming-the-simple-guide-to-events/1363122
[anth-adapter]: ../../../crates/chio-anthropic-tools-adapter/src/adapter.rs
[anth-stream]: ../../../crates/chio-anthropic-tools-adapter/src/streaming.rs
