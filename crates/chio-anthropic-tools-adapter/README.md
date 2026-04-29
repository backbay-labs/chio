# chio-anthropic-tools-adapter

Provider-native adapter that mediates Anthropic Messages API tool-use
traffic through the Chio kernel. Implements the
[`chio-tool-call-fabric`](../chio-tool-call-fabric/) `ProviderAdapter`
trait so a single Chio policy file enforces uniformly across OpenAI
Responses, Anthropic Messages, and Bedrock Converse.

## Pinned upstream API

- `anthropic-version: 2023-06-01` (verbatim header value).
- Exposed in code as `chio_anthropic_tools_adapter::transport::ANTHROPIC_VERSION`.
- Recorded in `Cargo.toml` under `[package.metadata.chio]`.

Bumping the pin is a deliberate PR with a fixture re-record; CI never
auto-bumps. See `.planning/trajectory/07-provider-native-adapters.md`,
"Pinned upstream API versions" section.

## Cargo features

| Feature        | Default | Effect                                                                                                     |
| -------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `computer-use` | off     | Compiles the Anthropic server-tool variants (`computer_use_20241022`, `bash_20241022`, `text_editor_20241022`) and lets the transport stamp `anthropic-beta: computer-use-2025-01-24` on outgoing requests. |

The `computer-use` feature alone is not sufficient to enable the
server-tool surface at runtime. M07.P3.T4 adds a `chio-manifest`
`server_tools: [...]` allowlist that the adapter consults at lift time
through `AnthropicAdapter::new_with_manifest`. Default deny applies even
with the feature on, including when `AnthropicAdapter::new` is used without
manifest wiring.

## M07.P3 ticket sequence

| Ticket | Deliverable                                                                  | Status |
| ------ | ---------------------------------------------------------------------------- | ------ |
| T1     | Crate scaffold, API pin, `computer-use` feature, native types, transport trait | landed |
| T2     | `ProviderAdapter::lift`/`lower` for batch `messages.create` tool_use blocks  | landed |
| T3     | SSE streaming with verdict at `content_block_start` for `tool_use`           | landed |
| T4     | `chio-manifest` `server_tools` allowlist gating the beta surface             | landed |
| T5     | 12 conformance fixtures (incl. 2 server-tool sessions behind the feature)    | pending |
| T6     | Native-error envelope -> `ProviderError` taxonomy doctest                    | landed |

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
surface an `error` event after a 200 response. This crate currently owns the
mockable transport trait, batch lift/lower, and SSE gate. It does not yet
ship a real HTTP client, so rows marked `HTTP transport boundary` pin the
adapter-visible taxonomy that the eventual transport must preserve. Rows
marked `current adapter path` are emitted by the current lift/lower,
streaming, or evaluator path.

The table is parsed by `tests/error_taxonomy_doctest.rs`; keep each envelope
as one valid inline JSON object.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"type":"error","error":{"type":"rate_limit_error","message":"rate limit reached"},"request_id":"req_rate"}}` | HTTP transport boundary | Preserve the retry hint as `retry_after_ms` when the native response carries one. |
| `ProviderError::ContentPolicy` | `{"status":200,"body":{"type":"message","id":"msg_refusal","role":"assistant","content":[{"type":"text","text":""}],"stop_reason":"refusal"}}` | HTTP transport boundary | Surface provider refusal as content-policy denial rather than a tool execution error. |
| `ProviderError::BadToolArgs` | `{"type":"tool_use","id":"toolu_bad_args","name":"get_weather","input":"not an object"}` | current adapter path | Fail closed when Anthropic emits a `tool_use.input` that cannot become canonical JSON object arguments. |
| `ProviderError::Upstream5xx` | `{"status":529,"body":{"type":"error","error":{"type":"overloaded_error","message":"overloaded"},"request_id":"req_overloaded"}}` | HTTP transport boundary | Keep upstream 5xx and overload bodies visible for retry and audit policy. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.anthropic.com/v1/messages","elapsed_ms":30000}` | HTTP transport boundary | Classify local transport timeout separately from Anthropic 504 `timeout_error` envelopes. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"anthropic","event":"content_block_start","observed_ms":300,"budget_ms":250}` | current adapter path | Preserve the fabric verdict-budget error when the evaluator misses the 250ms gate. |
| `ProviderError::Malformed` | `{"event":"content_block_delta","data":{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}}` | current adapter path | Fail closed for impossible or out-of-order native SSE/message shapes. |
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
    lib.rs           AnthropicAdapter, AnthropicAdapterConfig, error type
    manifest.rs      manifest-derived server-tool allowlist gate
    transport.rs     Transport trait, MockTransport, ANTHROPIC_VERSION pin
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

Both invocations must succeed for T1 to merge (gate-check defined in
`.planning/trajectory/tickets/M07/P3.yml`).

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"`
  apply; no exceptions.
- Fail-closed: server-tool requests without the `computer-use` feature
  surface a structured error rather than silently downgrading.

## References

- Trajectory doc: `.planning/trajectory/07-provider-native-adapters.md`
  Phase 3 (lines 393-420).
- Ticket spec: `.planning/trajectory/tickets/M07/P3.yml` (T4).
- Fabric trait surface: `crates/chio-tool-call-fabric/src/lib.rs`.
- Conformance harness skeleton: `crates/chio-provider-conformance/`
  (lands in M07.P2).
