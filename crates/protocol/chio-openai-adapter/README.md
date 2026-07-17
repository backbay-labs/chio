# chio-openai-adapter

OpenAI tool-call adapter for Chio. The default surface intercepts Chat
Completions and Responses API tool calls and dispatches them through the Chio
kernel for capability validation and signed receipts. The `provider-adapter`
feature adds a second, independent surface: lift/lower into the shared
`chio-tool-call-fabric` `ToolInvocation` shape, SSE streaming verdict gating,
and an outbound HTTP transport that forwards native requests to the OpenAI
API.

The crate publishes the library `chio_openai` (package `chio-openai-adapter`).
The default build never pulls in `chio-tool-call-fabric` or
`chio-provider-adapter-core`; enabling `provider-adapter` does not change
default-surface behavior. The crate forbids `unsafe` code.

## Responsibilities

- Convert Chio `ToolManifest`s into OpenAI Chat Completions tool definitions
  and extract tool calls back out of Chat Completions messages or Responses
  API output (`ChioOpenAiAdapter`).
- Dispatch each extracted tool call through the kernel
  (`ChioKernel::evaluate_tool_call_blocking_with_metadata`), planning an
  authoritative route via `chio-cross-protocol` first, and return a signed
  `ChioReceipt` for every call that reaches kernel evaluation.
- (`provider-adapter`) Implement `chio_tool_call_fabric::ProviderAdapter`:
  lift Responses API `function_call` items into `ToolInvocation`, lower a
  kernel `VerdictResult` into OpenAI `tool_outputs` JSON.
- (`provider-adapter`) Gate Responses API SSE streams so a buffered
  tool-call block reaches the caller only after its verdict allows it.
- (`provider-adapter`) Forward native `/v1/responses` and
  `/v1/chat/completions` requests to the OpenAI API over the shared
  `chio-provider-adapter-core` HTTP transport, with a `MockHttpTransport`
  seam for hermetic tests.

## Public API

Default surface, always compiled (superseded by `provider-adapter` for
provider-native mediation, see `CHANGELOG.md`, but still fully compiled and
tested):

- `ChioOpenAiAdapter` - `new`, `manifest`, `openai_tools`,
  `openai_tools_json`, `function_names`, `function_def`, `execute_tool_call`,
  `execute_tool_calls`, `results_to_messages`, `results_to_responses_api`,
  `extract_tool_calls`, `extract_responses_api_calls`.
- `OpenAiAdapterConfig` - manifest-generation config (`server_id`,
  `server_name`, `server_version`, `public_key`).
- `OpenAiExecutionContext` - per-batch execution input: capability token,
  agent id, DPoP proof, execution nonces keyed by OpenAI tool-call id,
  governed intent/approval token, model metadata.
- `OpenAiToolDef`, `OpenAiFunctionDef`, `OpenAiToolCall`, `OpenAiFunctionCall`,
  `ResponsesApiOutput`, `ToolCallResult`, `OpenAiAdapterError`.

`provider-adapter` feature also exposes:

- `OpenAiAdapter` (re-exported from `adapter`) - implements `ProviderAdapter`
  (`lift`, `lower`); also `lift_batch`, which lifts every `function_call`
  item in one payload, and `gate_sse_stream` for the streaming path.
- `OpenAiProviderAdapterConfig` - `adapter::OpenAiAdapterConfig` (`org_id`,
  `api_version`) re-exported under this alias because the plain name would
  collide with the default surface's `OpenAiAdapterConfig` above.
- `OPENAI_RESPONSES_API_VERSION` - the pinned Responses API snapshot
  (`"responses.2026-04-25"`). Every provider-adapter entry point rejects a
  configured `api_version` that does not match it.
- `streaming::{GatedSseStream, OpenAiSseTransport}` - not re-exported at the
  crate root; reach them through the `streaming` module.
- `transport::{OpenAiTransport, ChatCompletionsOutcome, OPENAI_API_BASE_URL,
  OPENAI_API_KEY_ENV, OPENAI_RESPONSES_PATH, OPENAI_CHAT_COMPLETIONS_PATH}` -
  also re-exported at the crate root.

## Feature flags

| Flag | Effect |
|------|--------|
| `provider-adapter` | Adds the `adapter`, `streaming`, and `transport` modules (the `ProviderAdapter` implementation, SSE verdict gating, and the outbound HTTP client). Pulls in `chio-tool-call-fabric` and `chio-provider-adapter-core`. |

## Error taxonomy (`provider-adapter`)

`ProviderError` classes an OpenAI provider-adapter caller can observe, with a
representative native or HTTP-boundary envelope for each. The classes and
envelopes are registered under `urn:chio:error:provider:openai`
(`CHIO-PROVIDER-OPENAI`) in `spec/errors/registry.yaml`.
`tests/error_taxonomy_doctest.rs` parses this table out of the README at test
time and checks it against live adapter behavior, so it cannot drift from the
code silently.

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

`ProviderError::Other` is intentionally absent: a native OpenAI envelope must
map to a concrete class above, or fail closed as `Malformed` when the shape
cannot be trusted.

## Testing

```
cargo test -p chio-openai-adapter
cargo test -p chio-openai-adapter --features provider-adapter
```

CI builds and tests both feature combinations; the default build must stay
free of the `provider-adapter` dependencies.
`cargo bench -p chio-openai-adapter --features provider-adapter` runs
`verdict_latency`, which panics before recording a Criterion sample if the
SSE gate's p99 latency exceeds a 250ms budget over 128 iterations.

## See also

- `chio-tool-call-fabric` - defines `ProviderAdapter` and the
  `ToolInvocation`/`VerdictResult` types the `provider-adapter` feature
  implements against.
- `chio-provider-adapter-core` - shared SSE parsing, HTTP transport, and
  error classification reused by every provider adapter.
- `chio-kernel` - evaluates every tool call the default surface dispatches.
- `chio-cross-protocol` - plans the authoritative route before each
  default-surface dispatch.
- `chio-provider-conformance` - replays fixtures against this adapter.
