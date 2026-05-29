# chio-anthropic-tools-adapter

Provider-native adapter that mediates Anthropic Messages API tool-use
traffic through the Chio kernel. Implements the
[`chio-tool-call-fabric`](../chio-tool-call-fabric/) `ProviderAdapter`
trait so a single Chio policy file enforces uniformly across OpenAI
Responses, Anthropic Messages, and Bedrock Converse.

## Transport

The adapter is a mediation gateway, not a validate-only shim. It forwards a
native `messages.create` request to `https://api.anthropic.com/v1/messages`
over the shared `chio-provider-adapter-core` HTTP transport, lifts the
`tool_use` content blocks out of the response, runs the kernel verdict, and
lowers the verdict back into a `tool_result` block for the next turn.

- `AnthropicAdapter::send_messages` posts a batch request and lifts the
  response.
- `AnthropicAdapter::send_messages_stream` posts a streaming request and runs
  the SSE gate over the buffered `text/event-stream` body.
- Outbound requests carry `x-api-key: <key>` plus the pinned
  `anthropic-version: 2023-06-01` header (and `anthropic-beta:
  computer-use-2025-01-24` when the `computer-use` feature is on).

The API key is injected by the caller through `anthropic_transport(api_key)` or
read from the `ANTHROPIC_API_KEY` environment variable through
`anthropic_transport_from_env()` (which fails closed when the variable is unset
or empty). Unit tests use the in-memory `MockTransport`, which records calls and
returns scripted responses without touching the network, so the test suite stays
offline and deterministic.

## Pinned upstream API

- `anthropic-version: 2023-06-01` (verbatim header value).
- Exposed in code as `chio_anthropic_tools_adapter::transport::ANTHROPIC_VERSION`.
- Recorded in `Cargo.toml` under `[package.metadata.chio]`.

Bumping the pin is a deliberate PR with a fixture re-record; CI never
auto-bumps.

## Cargo features

| Feature        | Default | Effect                                                                                                     |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `computer-use` | off     | Compiles the Anthropic server-tool variants (`computer_use_20241022`, `bash_20241022`, `text_editor_20241022`) and lets the transport stamp `anthropic-beta: computer-use-2025-01-24` on outgoing requests. |

The `computer-use` feature alone is not sufficient to enable the
server-tool surface at runtime. The adapter requires a `chio-manifest`
`server_tools: [...]` allowlist at lift time through
`AnthropicAdapter::new_with_manifest`. Default deny applies even with the
feature on, including when `AnthropicAdapter::new` is used without manifest
wiring.

## Components

| Component                                                                    |
| ---------------------------------------------------------------------------- |
| API pin, `computer-use` feature, native content-block types                  |
| `x-api-key` + `anthropic-version` HTTP transport (`send_messages`)           |
| `ProviderAdapter::lift`/`lower` for batch `messages.create` tool_use blocks  |
| SSE streaming with verdict at `content_block_stop` for `tool_use`            |
| `chio-manifest` `server_tools` allowlist gating the beta surface             |
| Native-error envelope -> `ProviderError` taxonomy doctest                    |

## Server-tool manifest gate

Anthropic server tools are provider-hosted beta surfaces. Chio treats them as
separate from regular client-hosted tools and fails closed unless both gates
are open:

1. Build the crate with `--features computer-use`.
2. Include the matching stable entry in the manifest `server_tools` allowlist:

```json
{
  "server_tools": ["computer_use", "bash", "text_editor"]
}
```

The adapter maps Anthropic's versioned wire names to the stable manifest
entries:

| Anthropic wire name        | Manifest entry |
| -------------------------- | -------------- |
| `computer_use_20241022`    | `computer_use` |
| `bash_20241022`            | `bash`         |
| `text_editor_20241022`     | `text_editor`  |

Unlisted server tools return a `ProviderError::Malformed` before the
`ToolInvocation` crosses the Chio trust boundary. Regular custom tools are
not affected by `server_tools` and continue through the normal capability and
guard path.

This differs from Bedrock Converse. Bedrock tool use is client-defined via
`toolConfig`; it does not have an Anthropic-managed `bash` server tool, so
Bedrock bash-like behavior is modeled as a normal customer tool and remains
outside this allowlist.

## Adapter-visible error taxonomy

Anthropic documents HTTP errors as JSON envelopes with a top-level
`error.type` and `error.message`, plus a `request_id`; streaming can also
surface an `error` event after a 200 response. Rows marked `HTTP transport
boundary` are mapped from the upstream HTTP status by
`chio_provider_adapter_core::http::map_transport_error` when `send_messages`
runs. Rows marked `current adapter path` are emitted by the lift/lower,
streaming, or evaluator path.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"type":"error","error":{"type":"rate_limit_error","message":"rate limit reached"},"request_id":"req_rate"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Preserve the retry hint as `retry_after_ms` when the native response carries one. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::ContentPolicy` | `{"status":200,"body":{"type":"message","id":"msg_refusal","role":"assistant","content":[{"type":"text","text":""}],"stop_reason":"refusal"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Surface provider refusal as content-policy denial rather than a tool execution error. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::BadToolArgs` | `{"type":"tool_use","id":"toolu_bad_args","name":"get_weather","input":"not an object"}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Fail closed when Anthropic emits a `tool_use.input` that cannot become canonical JSON object arguments. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Upstream5xx` | `{"status":529,"body":{"type":"error","error":{"type":"overloaded_error","message":"overloaded"},"request_id":"req_overloaded"}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Keep upstream 5xx and overload bodies visible for retry and audit policy. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.anthropic.com/v1/messages","elapsed_ms":30000}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + HTTP transport boundary | Anthropic provider adapter returned a normalized provider error. Classify local transport timeout separately from Anthropic 504 `timeout_error` envelopes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"anthropic","event":"content_block_start","observed_ms":300,"budget_ms":250}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Preserve the fabric verdict-budget error when the evaluator misses the 250ms gate. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
| `ProviderError::Malformed` | `{"event":"content_block_delta","data":{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}}` | `urn:chio:error:provider:anthropic` (`CHIO-PROVIDER-ANTHROPIC`) + current adapter path | Anthropic provider adapter returned a normalized provider error. Fail closed for impossible or out-of-order native SSE/message shapes. Registry help: Inspect the provider error details and retry only when the adapter marks the failure transient. |
<!-- error-taxonomy:end -->

`ProviderError::Other` is intentionally absent. Native Anthropic envelopes
must map to a concrete class above, or fail closed as `Malformed` when the
shape cannot be trusted.

## Crate layout

```text
crates/chio-anthropic-tools-adapter/
  Cargo.toml         pin metadata, computer-use feature, workspace lints
  README.md          this file
  src/
    lib.rs           AnthropicAdapter, send_messages, AnthropicAdapterConfig, error type
    manifest.rs      manifest-derived server-tool allowlist gate
    transport.rs     HttpTransport builders, MockTransport, ANTHROPIC_VERSION pin
    native.rs        ToolUseBlock, ToolResultBlock, server-tool variants
```

Batch `lift`/`lower` lives in `src/adapter.rs`, and SSE state-machine wiring
lives in `src/streaming.rs`.

## Building

```bash
cargo build -p chio-anthropic-tools-adapter
cargo build -p chio-anthropic-tools-adapter --features computer-use
cargo test -p chio-anthropic-tools-adapter --features computer-use server_tools
```

Both invocations must succeed in CI.

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"`
  apply; no exceptions.
- Fail-closed: server-tool requests without the `computer-use` feature
  surface a structured error rather than silently downgrading.

## References

- Fabric trait surface: `crates/chio-tool-call-fabric/src/lib.rs`.
- Conformance harness skeleton: `crates/chio-provider-conformance/`.
