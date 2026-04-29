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
- **`provider-adapter` feature** (opt-in): the M07 `ProviderAdapter`
  surface from
  [`chio-tool-call-fabric`](../chio-tool-call-fabric/README.md). When
  enabled, this crate exposes lift/lower for OpenAI's Responses API
  and (in later tickets) an SSE streaming wrapper that enforces the
  kernel verdict at the tool-use block boundary.

The two surfaces are independent: nothing on the default build pulls
in `chio-tool-call-fabric`, and nothing on the `provider-adapter`
build removes the existing helpers.

## OpenAI Responses API snapshot pin

This crate pins to OpenAI Responses API snapshot **`2026-04-25`**.

- Source: https://platform.openai.com/docs/api-reference/responses
- Recorded in `Cargo.toml` under `[package.metadata.chio]` as
  `openai_responses_api_snapshot = "2026-04-25"`.
- Streaming event names captured in
  `crates/chio-provider-conformance/fixtures/openai/EVENTS.md`
  (lands in M07.P2.T5).

Bumping the pin is a deliberate PR. The bump must:

1. Update `[package.metadata.chio].openai_responses_api_snapshot`
   in this crate's `Cargo.toml`.
2. Update the snapshot string in this README.
3. Re-record every OpenAI fixture under
   `crates/chio-provider-conformance/fixtures/openai/`.
4. Update the streaming event-name table referenced by
   `EVENTS.md`.
5. Bump the `api_version` string returned by
   `<OpenAiAdapter as ProviderAdapter>::api_version()` (lands in
   M07.P2.T2 as `responses.2026-04-25`).

The Responses API is GA but evolving; the pin gates a re-record when
event names shift.

## `provider-adapter` feature contract

Enabling `provider-adapter` opts in to:

- An optional dependency on `chio-tool-call-fabric`, which supplies
  the `ProviderAdapter` trait, `ToolInvocation`,
  `ProvenanceStamp`, `Principal`, `VerdictResult`, `DenyReason`,
  and `ProviderError` types.
- New modules (lands incrementally across M07.P2):
  - `adapter` (M07.P2.T2 / T3): `OpenAiAdapter` implementing
    `ProviderAdapter::lift` for batch `responses.create` and
    `ProviderAdapter::lower` for the kernel verdict, including the
    deny-synthetic `tool_outputs` path.
  - `streaming` (M07.P2.T4.a / T4.b): SSE transport plus
    per-block buffering wired into the fabric `StreamPhase`
    state machine. Verdict fires once at the first
    `response.output_item.added` event of type `tool_call`;
    subsequent `response.function_call_arguments.delta` events
    are buffered until the verdict resolves, then flushed on
    Allow or dropped on Deny.

This ticket (**M07.P2.T1**) wires only the feature flag, the
optional dependency, and this README's contract. No public adapter
API is added yet; the symbols above land in the follow-on tickets.

The feature is **opt-in**. Downstream consumers who only want the
existing Chat Completions helpers do not need to enable it. The
crate must build both with and without the feature; the gate-check
covers both.

## Adapter-visible error taxonomy

OpenAI surfaces request failures as JSON error envelopes with a
`body.error` object, while tool-call and streaming boundary failures can
arrive as native Responses API items or deterministic SSE frames. This crate
currently owns batch lift/lower and SSE gating, but it does not ship a real
HTTP client. Rows marked `HTTP transport boundary` pin the adapter-visible
taxonomy that any future transport must preserve. Rows marked `current
adapter path` are emitted by the current lift/lower, streaming, or evaluator
path.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"error":{"type":"rate_limit_exceeded","message":"Rate limit reached","code":"rate_limit_exceeded","param":null},"request_id":"req_openai_rate"}}` | HTTP transport boundary | Preserve the retry hint as `retry_after_ms` when the OpenAI response carries one. |
| `ProviderError::ContentPolicy` | `{"status":400,"body":{"error":{"type":"invalid_request_error","message":"Request rejected by content policy","code":"content_policy_violation","param":null},"request_id":"req_openai_policy"}}` | HTTP transport boundary | Surface provider refusal or policy rejection as content-policy denial rather than a tool execution error. |
| `ProviderError::BadToolArgs` | `{"type":"function_call","call_id":"call_bad_args","name":"get_weather","arguments":"{not json"}` | current adapter path | Fail closed when OpenAI emits function-call arguments that cannot become canonical JSON arguments. |
| `ProviderError::Upstream5xx` | `{"status":500,"body":{"error":{"type":"server_error","message":"Internal server error","code":"server_error","param":null},"request_id":"req_openai_500"}}` | HTTP transport boundary | Keep upstream 5xx bodies visible for retry and audit policy. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.openai.com/v1/responses","elapsed_ms":30000}` | HTTP transport boundary | Classify local transport timeout separately from OpenAI 5xx envelopes. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"openai","event":"response.output_item.done","observed_ms":300,"budget_ms":250}` | current adapter path | Preserve the fabric verdict-budget error when the evaluator misses the 250ms gate. |
| `ProviderError::Malformed` | `{"event":"response.function_call_arguments.delta","data":{"type":"response.function_call_arguments.delta","output_index":0,"call_id":"call_orphan","delta":"{}"}}` | current adapter path | Fail closed for impossible or out-of-order native SSE/Responses shapes. |
<!-- error-taxonomy:end -->

`ProviderError::Other` is intentionally absent. Native OpenAI envelopes must
map to a concrete class above, or fail closed as `Malformed` when the shape
cannot be trusted.

## Migration path for downstream consumers

| Today (default features)                   | After M07.P2 closes (with `provider-adapter`)             |
| ------------------------------------------ | --------------------------------------------------------- |
| Direct use of `chio_openai` extractors     | Continues to compile; deprecation note lands in M07.P2.T8 |
| No fabric `ToolInvocation` integration     | `OpenAiAdapter` implements the fabric trait               |
| Manual SSE handling                        | `streaming` module enforces verdict at tool-use boundary  |
| No pinned API snapshot                     | Snapshot pinned to `2026-04-25` in `Cargo.toml`           |

To migrate:

1. Add `chio-openai = { ..., features = ["provider-adapter"] }` to
   your `Cargo.toml`.
2. Replace direct extractor calls with the `OpenAiAdapter`
   implementation of `ProviderAdapter::lift` (available after
   M07.P2.T2).
3. Route the kernel verdict through `ProviderAdapter::lower`
   (available after M07.P2.T3).
4. For streaming consumers, swap manual SSE wiring for the
   `streaming` module (available after M07.P2.T4.b).

The existing direct-use APIs remain compiled for one minor release
after M07 closes; M07.P2.T8 lands the matching CHANGELOG entry. Rust
`#[deprecated]` markers are deferred unless a removal release is scheduled
separately.

## Build matrix

```bash
# Existing public surface only:
cargo build -p chio-openai

# Full M07 ProviderAdapter surface:
cargo build -p chio-openai --features provider-adapter
```

Both must succeed; CI enforces this via the M07.P2.T1 gate-check.

## House rules

- No em dashes anywhere (use hyphens or parentheses).
- Workspace clippy lints `unwrap_used = "deny"` and
  `expect_used = "deny"` are enforced.
- Fail-closed: errors deny access; invalid policies reject at load.

## Cross-references

- Milestone doc:
  [`.planning/trajectory/07-provider-native-adapters.md`](../../.planning/trajectory/07-provider-native-adapters.md)
  Phase 2.
- Fabric trait surface:
  [`crates/chio-tool-call-fabric/src/lib.rs`](../chio-tool-call-fabric/src/lib.rs).
- Spec: [`spec/PROTOCOL.md`](../../spec/PROTOCOL.md).
