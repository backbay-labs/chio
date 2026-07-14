# chio-ollama-tools-adapter architecture

## Overview

`chio-ollama-tools-adapter` is a provider-native edge adapter: it speaks
Ollama's native `/api/chat` HTTP and NDJSON wire format on one side and the
`chio_tool_call_fabric` contract (`ToolInvocation` in, `VerdictResult` /
`ToolResult` out) on the other. It holds no kernel state; every lifted tool call
is evaluated by a caller-supplied verdict closure before results are forwarded.
It does not implement a kernel-facing tool-server trait the way `chio-mcp-adapter`
implements `ToolServerConnection` - callers invoke `chat` / `chat_stream` /
`gate_sse_stream` directly and pass the evaluator in.

The adapter's central constraint is a hard pin to Ollama API snapshot `2025-04`.
`OllamaAdapterConfig` is serializable, so a persisted or hand-built config can
carry a stale `api_version`; every public entry point re-checks it against the
compiled-in `OLLAMA_API_VERSION` before doing any work.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `OllamaAdapter` handle and `OllamaAdapterConfig`; `chat`, `chat_stream`, `lift_batch`, `lower_tool_message`; the API-version guard; the `Provider` impl; tool-call validation, redaction application, and deny-payload rendering. |
| `src/transport.rs` | Ollama-specific `HttpTransportConfig` wiring: localhost default, `OLLAMA_HOST` / `OLLAMA_API_KEY` overrides, the `x-ollama-api-version` pin header, and the `Transport` / `MockTransport` re-exports. |
| `src/native.rs` | Wire types: `ToolCallPart`, `ToolCallFunction`, `ToolResultMessage`. |
| `src/response.rs` | Non-streaming `/api/chat` response parsing: unwraps an optional `body` / `response` / `payload` envelope, detects content-policy refusals, extracts `tool_calls`. |
| `src/streaming.rs` | `gate_sse_stream` and `GatedNdjsonStream`: line-by-line NDJSON gating against the caller's verdict closure. |
| `src/loaded_weights.rs` | `impl_unavailable_loaded_weights!` for `OllamaAdapter`; `OllamaLoadedWeights` for callers that hold local model bytes. |

## Request lifecycle

Non-streaming (`chat`):

1. `ensure_supported_api_version` fails closed before any I/O if the config's
   `api_version` differs from `OLLAMA_API_VERSION`.
2. `transport.post_json(OLLAMA_CHAT_PATH, request_body)` posts the raw request.
   `map_transport_error` classifies a transport-level failure (the real
   `HttpTransport` already turns a non-2xx status into one); `map_http_status`
   then re-checks the response status explicitly, covering a `Transport` such as
   `MockTransport` that can return a non-2xx status inside `Ok`.
3. `response::tool_calls` unwraps the optional envelope, runs
   `classify_content_policy`, and extracts `message.tool_calls`.
4. `invocation_from_tool_call` validates each call, canonical-JSON-encodes its
   arguments, and stamps a `ProvenanceStamp` with a synthesised
   `ollama_<name>_call_<index>` request id and `Principal::OllamaHost`.

Streaming (`chat_stream` / `gate_sse_stream`):

1. Same API-version guard.
2. `transport.post_ndjson` posts the request and returns the full response
   already buffered; there is no incremental delivery to the caller ahead of
   gating.
3. `gate_sse_stream` walks the body line by line. Each line is parsed as JSON
   and checked for a content-policy refusal; each `tool_calls` entry on that
   line is lifted, passed to the caller's `evaluate` closure, and checked with
   `ensure_streaming_allow_no_redactions` (an `Allow` verdict must carry no
   redactions; any `Deny` fails the call) before the line's bytes are appended
   to the forwarded output.

Lowering (`lower_tool_message`):

1. Same API-version guard, plus a non-empty, unpadded `tool_name` check.
2. `Allow`: parse the `ToolResult` bytes as JSON, apply each `Redaction`
   (whole-value replacement for an empty path, otherwise a JSON Pointer
   replacement), canonical-JSON-encode, and wrap in a `tool` role
   `ToolResultMessage`.
3. `Deny`: render `{"error": "<reason text>"}` and wrap the same way.

## Invariants and failure modes

- Every public entry point checks the API-version pin first and fails closed
  with `ProviderError::Malformed` before touching the transport, the evaluator,
  or provenance - `chat`, `chat_stream`, `lift_batch`, `gate_sse_stream`,
  `invocation_from_tool_call`, and `lower_tool_message` all call
  `ensure_supported_api_version` as their first step.
- A streaming `Allow` verdict that carries redactions is rejected: a line's
  bytes may already be scheduled for forwarding, so the adapter cannot redact
  after the fact. Redaction only happens on the non-streaming
  `lower_tool_message` path.
- Content-policy refusals are detected before tool-call extraction on both the
  batch and streaming paths, so a refusal never reaches `ToolInvocation`
  construction.
- Tool names, and the `tool_name` passed to `lower_tool_message`, are rejected
  if empty or if they carry leading/trailing whitespace (`non_empty_str`).
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

Internal: `chio-core` is aliased to `chio-core-types`
(`chio-core = { package = "chio-core-types", ... }` in `Cargo.toml`) and
supplies `canonical_json_bytes`, `LoadedWeights`, `LoadedWeightsUnavailable`,
`loaded_weights_hash_of`. `chio-provider-adapter-core` supplies the
reqwest-backed HTTP transport (`HttpTransport`, `HttpTransportConfig`,
`MockHttpTransport`), `map_http_status`, `map_transport_error`,
`ensure_streaming_allow_no_redactions`, the `impl_unavailable_loaded_weights!`
macro, and the `Provider` trait this crate implements. `chio-tool-call-fabric`
defines the shared contract this adapter lifts into and lowers from:
`ToolInvocation`, `ProviderError`, `VerdictResult`, `DenyReason`, `Principal`,
`ProvenanceStamp`, `Redaction`, `ProviderId`, `ProviderRequest`, `ToolResult`.

External: `serde` / `serde_json` for wire (de)serialization, `thiserror` for
`OllamaAdapterError`. Dev-only: `tokio` (`macros`, `rt-multi-thread`) backs the
async tests.
