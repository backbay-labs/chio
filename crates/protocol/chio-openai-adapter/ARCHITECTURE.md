# chio-openai-adapter architecture

## Overview

The crate is an edge adapter: it translates OpenAI's tool-call wire formats
into Chio's internal shapes and back, and holds no policy authority of its
own. It carries two independent surfaces gated by the `provider-adapter`
feature, and they connect to the rest of the system differently. The default
surface (`src/lib.rs`, always compiled) depends on `chio-kernel` directly and
is a complete adapter: `ChioOpenAiAdapter::execute_tool_call` dispatches
straight into `ChioKernel::evaluate_tool_call_blocking_with_metadata` and
returns a signed receipt. The `provider-adapter` surface (`src/adapter.rs`,
`src/streaming.rs`, `src/transport.rs`) has no `chio-kernel` dependency at
all; it is a pure lift/lower/transport layer against the
`chio-tool-call-fabric` `ProviderAdapter` contract, where the actual verdict
is supplied by a caller-owned closure (streaming) or value (`lower`), not
produced inside this crate.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Default surface. `ChioOpenAiAdapter`: manifest merge and validation, Chat Completions tool-def generation, tool-call extraction from both APIs, kernel dispatch via `chio-cross-protocol` route planning, result rendering. Declares `OpenAiAdapterError`, `OpenAiAdapterConfig`, `OpenAiExecutionContext`. |
| `src/adapter.rs` | `provider-adapter` feature. `OpenAiAdapter` and `OpenAiAdapterConfig` (org id plus pinned API version). Implements `ProviderAdapter::lift`/`lower`. Owns `OPENAI_RESPONSES_API_VERSION` and `ensure_supported_api_version`. |
| `src/streaming.rs` | `provider-adapter` feature. `StreamGate`, `ActiveToolBlock`: SSE frame gating for one Responses API stream, buffering a tool-call block until its verdict resolves. |
| `src/transport.rs` | `provider-adapter` feature. `OpenAiTransport`: outbound HTTP client over `ProviderHttpTransport`, covering `/v1/responses`, `/v1/chat/completions`, and SSE streaming. |
| `src/tests.rs` | `#[cfg(test)]` unit coverage for the default surface: manifest conversion, extraction, kernel dispatch, response rendering. |

## Default surface: tool-call dispatch

1. `ChioOpenAiAdapter::new` merges one or more `ToolManifest`s into a
   function-name to `(server_id, tool_name)` binding table plus one combined
   `ToolManifest`, validated by `chio_manifest::validate_manifest`. The first
   manifest to claim a function name wins; later duplicates are dropped.
2. The caller extracts tool calls with `extract_tool_calls` (Chat Completions
   `message.tool_calls[]`) or `extract_responses_api_calls` (Responses API
   `output[]` items of type `function_call`). Both paths run every call
   through `validate_tool_call`: non-empty, untrimmed `call_id` and
   `function.name`, `call_type == "function"`, non-empty `arguments`.
3. `execute_tool_call` resolves the function binding, parses `arguments` as
   JSON, builds a `ToolCallRequest`, plans an authoritative route with
   `chio_cross_protocol::routing::plan_authoritative_route` (source
   `DiscoveryProtocol::OpenAi`, target `Native`), and calls
   `ChioKernel::evaluate_tool_call_blocking_with_metadata`.
4. An `Ok(response)` becomes a `ToolCallResult`. `denied` is true whenever the
   verdict is not `Allow`, or when it is `Allow` but the terminal state is
   `Incomplete` (an execution-nonce preflight, which also sets
   `preflight: true` and carries no tool output; `content` explains the retry
   path instead). A complete `Allow` renders the tool's output as `content`.
   Every `Ok` response carries the kernel's signed `ChioReceipt` regardless of
   `denied`/`preflight`; only failures before or during kernel evaluation
   (unknown function, unparseable arguments, route-planning failure, a kernel
   `Err`) short-circuit through `denied_tool_call_result` with no receipt.
5. `results_to_messages` / `results_to_responses_api` filter out preflight
   results and render the rest back into Chat Completions tool messages or
   Responses API `function_call_output` items.

## `provider-adapter` surface: lift and lower

- `OpenAiAdapter::lift_batch` accepts a plain Responses API response, a
  `{headers, body|response|payload}` envelope, or one bare `function_call`
  item; unwraps it with `chio_provider_adapter_core::nested_response_body`
  and the same `ChioOpenAiAdapter::extract_responses_api_calls` used by the
  default surface, then stamps each call into a `ToolInvocation` with a
  `ProvenanceStamp` (`Principal::OpenAiOrg`, the pinned `api_version`).
- `ProviderAdapter::lift` calls a private `lift_one`, which requires exactly
  one `function_call` item in the batch.
- `ProviderAdapter::lower` takes a `VerdictResult` and a `ToolResult` (one
  entry, accepted as a bare object, an array, or a `tool_outputs`/`outputs`
  envelope) and renders `tool_outputs` JSON: `Allow` applies JSON Pointer
  redactions to the stored output and serializes it; `Deny` synthesizes a
  `chio_denied_tool_call` payload carrying the deny reason and receipt id.

## `provider-adapter` surface: streaming

- `gate_sse_stream` parses raw SSE bytes with the canonical
  `chio-provider-adapter-core` parser, configured with the OpenAI `[DONE]`
  terminator and an event/`type` cross-check.
- One tool-call block is active at a time. `response.output_item.added`
  opens it; `response.function_call_arguments.delta` frames accumulate
  through the fabric `StreamPhase`; `response.function_call_arguments.done`
  closes the argument text. A second `output_item.added` before the active
  block finishes is rejected.
- `response.output_item.done` calls the caller's `evaluate` closure exactly
  once with the lifted `ToolInvocation`. The buffered delta bytes, the
  `arguments.done` text, and the `output_item.done` arguments must all agree
  byte-for-byte or the stream fails closed as `Malformed`.
- Only an `Allow` verdict with zero redactions releases the buffered frames
  into the output stream. A `Deny` verdict, a redacted `Allow`, or an
  `evaluate` error closes the phase and returns `Err` without forwarding the
  tool-call block; unlike the batch `lower` path, streaming never synthesizes
  a deny payload in-band.

## `provider-adapter` surface: outbound transport

- `OpenAiTransport` wraps `Arc<dyn ProviderHttpTransport>` (`HttpTransport`
  in production, `MockHttpTransport` in tests) with an `OpenAiAdapter`.
- `send_responses`, `send_chat_completions`, and `stream_responses` each call
  `ensure_supported_api_version` first, POST to the OpenAI endpoint, classify
  the HTTP status through the shared `map_http_status` before touching the
  body, and hand the body to the adapter's lift or gate path.
- `send_chat_completions` rewrites `choices[0].message.tool_calls[]` into a
  synthetic Responses API `output[]` envelope so both endpoints stamp
  provenance through the same `lift_batch` path.

## Invariants and failure modes

- The crate forbids `unsafe` (`#![forbid(unsafe_code)]`), and the two
  surfaces are additive: the default build has no `chio-tool-call-fabric` or
  `chio-provider-adapter-core` dependency, and `provider-adapter` changes
  nothing about default-surface behavior.
- Two distinct `OpenAiAdapterConfig` types exist by design: the crate-root
  one configures manifest generation; `adapter::OpenAiAdapterConfig` (org id
  plus API version) is re-exported at the crate root as
  `OpenAiProviderAdapterConfig` specifically to avoid the name collision.
- `ensure_supported_api_version` gates every `provider-adapter` entry point
  (`lift`, `lower`, `gate_sse_stream`, and all three `OpenAiTransport`
  methods) and fails closed with `ProviderError::Malformed` unless
  `config.api_version` equals the pinned `OPENAI_RESPONSES_API_VERSION`
  (`"responses.2026-04-25"`).
- Execution nonces in `OpenAiExecutionContext.execution_nonces` are
  single-use and keyed per OpenAI tool-call id; batch execution never reuses
  one nonce across multiple calls in the same batch.
- The `openai_responses_api_snapshot` metadata in `Cargo.toml`,
  `OPENAI_RESPONSES_API_VERSION`, and `OpenAiAdapter::api_version()` move
  together. Bumping the pin also requires re-recording the fixtures under
  `chio-provider-conformance/fixtures/openai/` and that directory's
  `EVENTS.md` streaming event table.
- `tests/error_taxonomy_doctest.rs` parses the error-taxonomy table out of
  `README.md` between the `<!-- error-taxonomy:start/end -->` markers and
  checks the class names and JSON envelopes against live adapter behavior;
  the table and the code must change together.

## Dependencies

- `chio-kernel` (default surface only): `ChioKernel`, `ToolCallRequest`,
  `ToolCallResponse`, `ToolCallOutput`, `SignedExecutionNonce`, `dpop` - the
  guard-pipeline dispatch target.
- `chio-manifest`: `ToolDefinition`, `ToolManifest`, `validate_manifest` -
  the tool-catalog shape shared with the kernel.
- `chio-cross-protocol`: `discovery`, `routing` - authoritative route
  planning before every default-surface dispatch.
- `chio-core` (dependency aliased to the `chio-core-types` package):
  `capability`, `receipt`, `session`, `canonical` types.
- `chio-tool-call-fabric` (optional, `provider-adapter`): the
  `ProviderAdapter` trait and the `ToolInvocation`/`VerdictResult`/
  `ProviderError`/`StreamPhase` types this feature implements against.
- `chio-provider-adapter-core` (optional, `provider-adapter`): SSE parsing,
  HTTP transport, and status/transport-error classification shared across
  provider adapters.

## Extension points

- `ProviderAdapter` (from `chio-tool-call-fabric`) is the trait
  `OpenAiAdapter` implements; other providers implement the same trait to
  plug into fabric-based dispatch alongside this one.
- `ProviderHttpTransport` (from `chio-provider-adapter-core::http`) is the
  seam `OpenAiTransport` is generic over: `MockHttpTransport` for hermetic
  tests, `HttpTransport` in production, or a caller-supplied implementation
  for a proxy or gateway.
