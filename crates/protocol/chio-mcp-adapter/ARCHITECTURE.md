# chio-mcp-adapter architecture note

## Boundaries

- `lib.rs` declares the public adapter modules and keeps the edge, native,
  transport, framing, manifest, loaded-weights, and fuzz boundaries distinct.
  It does not flatten those APIs at the crate root.
- `adapter.rs` owns `McpAdapterConfig`, `McpAdapter`, and
  `SerializedMcpTransport`.
- `server.rs` owns `AdaptedMcpServer` and its kernel `ToolServerConnection`
  implementation.
- `resources.rs` owns `AdaptedMcpResourceProvider` and resource/completion
  forwarding.
- `prompts.rs` owns `AdaptedMcpPromptProvider` and prompt/completion
  forwarding.
- `result_mapping.rs` owns wrapped MCP tool-result normalization.
- `errors.rs` owns adapter-error to kernel-error mapping.
- `url_elicitation.rs` owns URL-required elicitation admission and validation.
- `transport.rs` owns stdio JSON-RPC framing, upstream request routing, bounded frame reads, initialization, notification buffering, nested-flow request handling, task runtime state, and cancellation propagation.
- `framing.rs` owns MCP stdio frame decoding (newline delimiter, byte size, UTF-8, JSON parse) shared by `StdioMcpTransport` and the fuzz entrypoint.
- `manifest.rs` owns projection from `McpToolInfo` into Chio `ToolDefinition`, JSON schema validation, and MCP-annotation-to-side-effect translation.
- `native.rs` owns the native Chio authoring surface built around `NativeChioServiceBuilder`, including manifest emission and in-process tool/resource/prompt handlers.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for MCP surfaces that cannot expose native model bytes.
- `fuzz.rs` owns the feature-gated MCP envelope parse entrypoint for the standalone fuzz workspace.

## Trust Boundaries

- The stdio reader rejects EOF before the newline delimiter for non-empty frames. MCP stdio is newline-delimited JSON-RPC, so a delimiterless final JSON object is not a complete frame; `read_bounded_line` also enforces the maximum frame size. The production transport and the fuzz entrypoint route through `framing.rs`, so fuzz coverage matches the production delimiter, size, UTF-8, and JSON parse boundary.
- `SerializedMcpTransport` shares one upstream MCP transport across multiple Chio sessions. Every interaction that touches the shared upstream transport, including `drain_notifications`, passes through `with_request_gate`; only immutable `capabilities()` reads stay ungated so cached capability reads do not deadlock. Draining still returns whatever the inner transport exposes, without racing request-like calls.
- `manifest.rs` validates each MCP tool once through an internal projection type, folds the MCP `title` into the Chio description, then emits `ToolDefinition`. MCP annotation semantics are preserved: missing or malformed safety hints imply side effects, and `destructiveHint=true` overrides `readOnlyHint=true`.
- Wrapped MCP result normalization inserts `isError: false` when an MCP-shaped success result omits it, matching `chio-mcp-edge::runtime::protocol::value_to_tool_result`. Explicit upstream `isError` values and content/structuredContent bytes are preserved.
- `url_elicitation.rs` maps wrapped-server `-32042` errors into `KernelError::UrlElicitationsRequired`. It validates each URL-mode operation's `message`, `url`, and `elicitationId`, rejecting empty or padded identifiers and non-HTTP(S) or userinfo-bearing URLs before the kernel stores pending session state. Form-mode and mixed-mode elicitations are rejected on this wrapped-tool path.

## Constraints

- Preserve the public API for `McpAdapter`, `McpAdapterConfig`, `AdaptedMcpServer`, `SerializedMcpTransport`, `StdioMcpTransport`, native builder types, and re-exported MCP edge contracts.
- Preserve fail-closed behavior for malformed upstream metadata, JSON-RPC parse errors, transport failures, nested-flow denials, cancellation, and manifest validation.
- Preserve wire compatibility with the JSON-RPC schema docs and the stdio MCP newline framing.
- MCP hosting behavior lives in `chio-mcp-edge`; adapter changes must not move hosting responsibilities into this crate.

## Dependents

- `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, `chio-mcp-remote`, and `examples/hello-tool` depend on the public adapter and native-service APIs.
- `crates/protocol/chio-mcp-edge` owns first-class MCP hosting behavior.
- `spec/schemas/chio-wire/v1/jsonrpc` documents the transport JSON-RPC framing mirrored by `transport.rs`.
- `docs/start-here/NATIVE_ADOPTION_GUIDE.md` documents the native builder surface exposed from this crate.
