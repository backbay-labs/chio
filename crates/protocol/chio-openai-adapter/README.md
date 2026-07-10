# chio-openai

OpenAI tool-call adapter for Chio. Intercepts OpenAI-style tool_use /
function-calling traffic and routes it through the Chio kernel for
capability validation and signed-receipt issuance.

The crate publishes the library `chio_openai` (package
`chio-openai-adapter`).

## Surface

- **Default features**: the existing public surface (Chat Completions
  helpers and Responses-API extraction utilities). This is what
  in-tree consumers compile against today and is preserved verbatim.
- **`provider-adapter` feature** (opt-in): the `ProviderAdapter` surface from
  [`chio-tool-call-fabric`](../chio-tool-call-fabric/README.md). When
  enabled, this crate exposes lift/lower for OpenAI's Responses API, an SSE
  streaming wrapper that enforces the kernel verdict at the tool-use block
  boundary, and an outbound `OpenAiTransport` that forwards native requests to
  the OpenAI API over the shared
  [`chio-provider-adapter-core`](../chio-provider-adapter-core/README.md) HTTP
  transport.

The two surfaces are independent: nothing on the default build pulls
in `chio-tool-call-fabric`, and nothing on the `provider-adapter`
build removes the existing helpers.

## OpenAI Responses API snapshot pin

This crate pins to OpenAI Responses API snapshot **`2026-04-25`**.

- Source: https://platform.openai.com/docs/api-reference/responses
- Recorded in `Cargo.toml` under `[package.metadata.chio]` as
  `openai_responses_api_snapshot = "2026-04-25"`.
- Streaming event names captured in
  `crates/protocol/chio-provider-conformance/fixtures/openai/EVENTS.md`.

Bumping the pin is a deliberate PR. The bump must:

1. Update `[package.metadata.chio].openai_responses_api_snapshot`
   in this crate's `Cargo.toml`.
2. Update the snapshot string in this README.
3. Re-record every OpenAI fixture under
   `crates/protocol/chio-provider-conformance/fixtures/openai/`.
4. Update the streaming event-name table referenced by
   `EVENTS.md`.
5. Bump the `api_version` string returned by
   `<OpenAiAdapter as ProviderAdapter>::api_version()` as
   `responses.2026-04-25`.

The Responses API is GA but evolving; the pin gates a re-record when
event names shift.

## `provider-adapter` feature contract

Enabling `provider-adapter` opts in to:

- An optional dependency on `chio-tool-call-fabric`, which supplies
  the `ProviderAdapter` trait, `ToolInvocation`,
  `ProvenanceStamp`, `Principal`, `VerdictResult`, `DenyReason`,
  and `ProviderError` types.
- New modules exposed by the provider adapter feature:
  - `adapter`: `OpenAiAdapter` implementing
    `ProviderAdapter::lift` for batch `responses.create` and
    `ProviderAdapter::lower` for the kernel verdict, including the
    deny-synthetic `tool_outputs` path.
  - `streaming`: SSE transport plus per-block buffering wired into the
    fabric stream state machine. Verdict fires once at the first
    `response.output_item.added` event of type `tool_call`;
    subsequent `response.function_call_arguments.delta` events
    are buffered until the verdict resolves, then flushed on
    Allow or dropped on Deny. The SSE parser is the canonical one in
    `chio-provider-adapter-core` (configured with the OpenAI `[DONE]`
    terminator and the event/`type` cross-check).
  - `transport`: `OpenAiTransport`, a real outbound client built on the shared
    `chio-provider-adapter-core` HTTP transport. It POSTs to `/v1/responses`
    and `/v1/chat/completions` with `Authorization: Bearer <OPENAI_API_KEY>`,
    parses tool calls back into the adapter types, and lifts them into the
    canonical invocation shape. A `MockHttpTransport` constructor seam keeps
    tests hermetic (no live network).

The feature is **opt-in**. Downstream consumers who only want the
existing Chat Completions helpers do not need to enable it. The
crate must build both with and without the feature; the build check
covers both.

## Adapter-visible error taxonomy

OpenAI surfaces request failures as JSON error envelopes with a
`body.error` object, while tool-call and streaming boundary failures can
arrive as native Responses API items or deterministic SSE frames. This crate
owns batch lift/lower, SSE gating, and (under the `provider-adapter` feature)
the outbound HTTP transport. Rows marked `HTTP transport boundary` are emitted
by that transport (via `OpenAiTransport`), which maps upstream HTTP status and
transport failures through the shared `chio-provider-adapter-core` classifier.
Rows marked `current adapter path` are emitted by the lift/lower, streaming, or
evaluator path.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"error":{"type":"rate_limit_exceeded","message":"Rate limit reached","code":"rate_limit_exceeded","param":null},"request_id":"req_openai_rate"}}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + HTTP transport boundary | OpenAI provider adapter returned a normalized provider error. Preserve the retry hint as `retry_after_ms` when the OpenAI response carries one. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::ContentPolicy` | `{"status":400,"body":{"error":{"type":"invalid_request_error","message":"Request rejected by content policy","code":"content_policy_violation","param":null},"request_id":"req_openai_policy"}}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + HTTP transport boundary | OpenAI provider adapter returned a normalized provider error. Surface provider refusal or policy rejection as content-policy denial rather than a tool execution error. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::BadToolArgs` | `{"type":"function_call","call_id":"call_bad_args","name":"get_weather","arguments":"{not json"}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + current adapter path | OpenAI provider adapter returned a normalized provider error. Fail closed when OpenAI emits function-call arguments that cannot become canonical JSON arguments. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Upstream5xx` | `{"status":500,"body":{"error":{"type":"server_error","message":"Internal server error","code":"server_error","param":null},"request_id":"req_openai_500"}}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + HTTP transport boundary | OpenAI provider adapter returned a normalized provider error. Keep upstream 5xx bodies visible for retry and audit policy. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.openai.com/v1/responses","elapsed_ms":30000}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + HTTP transport boundary | OpenAI provider adapter returned a normalized provider error. Classify local transport timeout separately from OpenAI 5xx envelopes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"openai","event":"response.output_item.done","observed_ms":300,"budget_ms":250}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + current adapter path | OpenAI provider adapter returned a normalized provider error. Preserve the fabric verdict-budget error when the evaluator misses the 250ms gate. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Malformed` | `{"event":"response.function_call_arguments.delta","data":{"type":"response.function_call_arguments.delta","output_index":0,"call_id":"call_orphan","delta":"{}"}}` | `urn:chio:error:provider:openai` (`CHIO-PROVIDER-OPENAI`) + current adapter path | OpenAI provider adapter returned a normalized provider error. Fail closed for impossible or out-of-order native SSE/Responses shapes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
<!-- error-taxonomy:end -->

`ProviderError::Other` is intentionally absent. Native OpenAI envelopes must
map to a concrete class above, or fail closed as `Malformed` when the shape
cannot be trusted.

## Migration path for downstream consumers

| Today (default features)                   | With `provider-adapter` enabled                           |
| ------------------------------------------ | --------------------------------------------------------- |
| Direct use of `chio_openai` extractors     | Continues to compile; deprecation note lands separately   |
| No fabric `ToolInvocation` integration     | `OpenAiAdapter` implements the fabric trait               |
| Manual SSE handling                        | `streaming` module enforces verdict at tool-use boundary  |
| No pinned API snapshot                     | Snapshot pinned to `2026-04-25` in `Cargo.toml`           |

To migrate:

1. Add `chio-openai = { ..., features = ["provider-adapter"] }` to
   your `Cargo.toml`.
2. Replace direct extractor calls with the `OpenAiAdapter`
   implementation of `ProviderAdapter::lift`.
3. Route the kernel verdict through `ProviderAdapter::lower`.
4. For streaming consumers, swap manual SSE wiring for the
   `streaming` module.

The existing direct-use APIs remain compiled for one minor release
after the adapter surface is complete. Rust
`#[deprecated]` markers are deferred unless a removal release is scheduled
separately.

## Build matrix

```bash
# Existing public surface only:
cargo build -p chio-openai

# Full ProviderAdapter surface:
cargo build -p chio-openai --features provider-adapter
```

Both must succeed; CI enforces this build matrix.

## House rules

- No em dashes anywhere (use hyphens or parentheses).
- Workspace clippy lints `unwrap_used = "deny"` and
  `expect_used = "deny"` are enforced.
- Fail-closed: errors deny access; invalid policies reject at load.

## Cross-references

- Fabric trait surface:
  [`crates/protocol/chio-tool-call-fabric/src/lib.rs`](../chio-tool-call-fabric/src/lib.rs).
- Spec: [`spec/PROTOCOL.md`](../../../spec/PROTOCOL.md).
