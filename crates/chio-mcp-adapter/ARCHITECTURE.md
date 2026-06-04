# chio-mcp-adapter architecture note

## Boundaries

- `lib.rs` owns the public wrapped-MCP adapter facade, adapted server/provider wrappers, serialized transport wrapper, and kernel-facing error mapping.
- `transport.rs` owns stdio JSON-RPC framing, upstream request routing, bounded frame reads, initialization, notification buffering, nested-flow request handling, task runtime state, and cancellation propagation.
- `native.rs` owns the native Chio authoring surface built around `NativeChioServiceBuilder`, including manifest emission and in-process tool/resource/prompt handlers.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for MCP surfaces that cannot expose native model bytes.
- `fuzz.rs` owns the feature-gated MCP envelope parse entrypoint for the standalone fuzz workspace.

## Pain Points

- `lib.rs` mixes public adapter orchestration with MCP-to-Chio manifest projection and tool annotation interpretation.
- `transport.rs` owns both subprocess lifecycle and low-level stdio framing, so frame boundary drift is easy to miss during nested-flow changes.
- `read_bounded_line` enforces the maximum frame size, but it also defines whether EOF can terminate a frame.
- The crate has good behavior tests, but the stdio frame trust boundary needs explicit coverage for truncated or delimiterless upstream output.
- `SerializedMcpTransport` gates request-like calls through one mutex, but notification draining is also shared transport access and must not bypass that gate when sessions share one wrapped MCP process.

## Constraints

- Preserve the public API for `McpAdapter`, `McpAdapterConfig`, `AdaptedMcpServer`, `SerializedMcpTransport`, `StdioMcpTransport`, native builder types, and re-exported MCP edge contracts.
- Preserve fail-closed behavior for malformed upstream metadata, JSON-RPC parse errors, transport failures, nested-flow denials, cancellation, and manifest validation.
- Preserve existing MCP annotation semantics: missing or malformed safety hints imply side effects; `destructiveHint=true` overrides `readOnlyHint=true`.
- Preserve wire compatibility with the JSON-RPC schema docs and the stdio MCP newline framing.
- Keep this slice scoped to the adapter crate unless a dependent gate proves a transitive change is required.

## Dependents

- `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, `chio-mcp-remote`, and `examples/hello-tool` depend on the public adapter and native-service APIs.
- `crates/chio-mcp-edge` owns first-class MCP hosting behavior; adapter changes must not move hosting responsibilities back into this crate.
- `spec/schemas/chio-wire/v1/jsonrpc` documents the transport JSON-RPC framing mirrored by `transport.rs`.
- `docs/start-here/NATIVE_ADOPTION_GUIDE.md` documents the native builder surface exposed from this crate.

## Planned Improvement

Make the stdio reader reject EOF before the newline delimiter for non-empty frames. This is architectural because MCP stdio is newline-delimited JSON-RPC, so accepting a delimiterless final JSON object weakens the frame boundary and lets a dying upstream process complete a Chio-visible response without producing a complete MCP frame.

## Serialized Notification Drain Slice

### Current Boundary

`SerializedMcpTransport` is the adapter-owned wrapper for sharing one upstream MCP transport across multiple Chio sessions. Its contract is stronger than delegation: every interaction that touches the shared upstream transport should pass through the same request gate unless it is immutable capability metadata.

### Pain Point

Most transport methods use `with_request_gate`, but `drain_notifications` calls the inner transport directly. That creates a second concurrent access path into an MCP subprocess wrapper exactly where queued notifications, in-flight request routing, nested-flow updates, and task notifications meet. The existing test only asserted that draining returned an empty vector; it did not prove serialization.

### Security And API Constraints

- Preserve the public `SerializedMcpTransport::from_arc` API and all `McpTransport` method signatures.
- Preserve notification semantics: draining still returns whatever the inner transport exposes, just without racing request-like calls.
- Keep immutable `capabilities()` ungated so local cached capability reads remain cheap and do not deadlock.
- Do not move MCP hosting behavior from `chio-mcp-edge` into this adapter slice.

### Affected Dependents

No dependent crate API should change. `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, and `chio-mcp-remote` depend on the adapter surface and should continue to compile unchanged. The focused proof is a crate-local test that holds the request gate in `call_tool` and proves `drain_notifications` cannot complete until the gate is released.

### Planned Improvement

Route `SerializedMcpTransport::drain_notifications` through `with_request_gate` and replace the empty delegation test with a concurrency regression that fails if notification draining bypasses the shared upstream gate.

## Shared Stdio Framing Slice

### Current Boundary

`transport.rs` owns the production MCP stdio reader, while `fuzz.rs` owns the feature-gated envelope parse entrypoint used by the fuzz workspace.

### Pain Point

The production reader now rejects non-empty EOF before a newline delimiter, but the fuzz entrypoint still uses `std::io::BufRead::read_line` directly and therefore accepts a delimiterless final JSON object as a parse candidate. That makes the fuzz target slightly weaker than the production trust boundary it claims to exercise.

### Security And API Constraints

- Preserve the public `McpAdapter`, `StdioMcpTransport`, and fuzz feature APIs.
- Preserve the production wire contract: MCP stdio messages are newline-delimited JSON-RPC frames with a bounded byte size.
- Preserve fail-closed behavior for invalid JSON, invalid UTF-8, oversized frames, and truncated frames.
- Keep fuzz instrumentation behind the `fuzz` feature and keep production builds free of `arbitrary`.

### Affected Dependents

No downstream crate API should change. `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, `chio-mcp-remote`, and `examples/hello-tool` should continue to compile unchanged. The focused proof is crate-local transport and fuzz-feature tests.

### Planned Improvement

Extract MCP stdio frame decoding into an internal `framing` module and route both `StdioMcpTransport` and `fuzz_mcp_envelope_parse` through it so fuzz coverage matches the production delimiter, size, UTF-8, and JSON parse boundary.

## MCP Tool Description Projection Slice

### Current Boundary

`manifest.rs` owns projection from `McpToolInfo` into Chio `ToolDefinition`. It validates JSON schemas and translates MCP safety annotations into Chio side-effect metadata.

### Pain Point

`McpToolInfo` includes a display `title`, but the current manifest projection drops it because `ToolDefinition` has only a `description` field. That loses upstream discovery metadata before the kernel, cross-protocol bridges, CLI surfaces, and LLM-facing tool selectors can see it. The execution plan calls out metadata preservation for wrapped MCP tools; output schemas and annotation-derived side effects are covered, but title is not.

### Security And API Constraints

- Preserve the public `McpToolInfo`, `McpAdapter`, and `ToolDefinition` APIs.
- Keep schema validation and fail-closed side-effect inference unchanged.
- Do not add a new manifest field or generated schema change in this adapter slice.
- Do not preserve raw execution metadata until the manifest format has a typed destination for it.

### Affected Dependents

No downstream Rust API changes. `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, `chio-mcp-remote`, and cross-protocol bridges receive richer manifest descriptions when wrapped MCP servers advertise titles. Existing description-only tools keep the same description text.

### Planned Improvement

Introduce an internal manifest projection type that validates the MCP tool once, preserves MCP title by folding it into the Chio description, and then emits `ToolDefinition`. This is architectural because it gives `manifest.rs` an explicit admission/projection boundary instead of scattering MCP-field interpretation directly inside `ToolDefinition` construction.

## Wrapped Tool Result Normalization Slice

### Current Boundary

`lib.rs` owns the adapter-facing conversion from upstream `McpToolResult` into
the Chio-visible JSON value returned by `McpAdapter::invoke` and
`AdaptedMcpServer::invoke`. `chio-mcp-edge` owns the inverse hosting path from
Chio tool output into MCP `tools/call` results.

### Pain Point

The hosting edge inserts `isError: false` when an MCP-shaped success result
omits `isError`, but the wrapped adapter currently preserves the omission. That
creates two Chio-owned MCP result shapes for the same success state. Downstream
bridges and task-status projection use `isError` as the explicit success/error
switch, so the wrapped path should not force every caller to rediscover the MCP
default.

### Security And API Constraints

- Preserve `McpToolResult` deserialization compatibility with upstream MCP
  servers that omit `isError`.
- Preserve explicit upstream `isError: true` and `isError: false` values.
- Preserve content and structuredContent byte values exactly except for adding
  the missing boolean default.
- Do not change manifest projection, guard ordering, nested-flow behavior,
  notification handling, or edge hosting behavior in this adapter slice.

### Affected Dependents

No dependent Rust API changes are expected. `chio-cli`, `chio-control-plane`,
`chio-hosted-mcp`, and `chio-mcp-remote` receive a more explicit JSON result
from wrapped MCP calls when upstream omits `isError`.

### Implemented Improvement

Wrapped MCP result normalization now inserts `isError: false` when upstream
omits it, matching `chio-mcp-edge::runtime::protocol::value_to_tool_result`.
Helper and invocation tests prove the adapter boundary cannot regress to an
ambiguous success shape.

## URL-Required Elicitation Admission Slice

### Current Boundary

`lib.rs` maps wrapped MCP server `-32042` errors into
`KernelError::UrlElicitationsRequired` so a Chio session can surface
browser-mediated URL elicitations and later match completion notifications by
`elicitationId`.

### Pain Point

The mapper currently checks only that `data.elicitations` deserializes into
URL-mode `CreateElicitationOperation` values. It does not reject empty or
padded `message`, `url`, or `elicitationId` fields, and it does not prove that
the URL is a browser-safe HTTP(S) URL before the kernel stores the elicitation
ID as pending session state.

### Security And API Constraints

- Preserve standard `-32042` URL-required error mapping for well-formed HTTPS
  and HTTP URL elicitations.
- Keep form-mode or mixed-mode elicitations rejected on this wrapped-tool
  error path.
- Do not move session storage or edge-hosted completion ownership into this
  adapter crate.
- Reject malformed URL-required payloads before they become kernel errors or
  pending session identifiers.

### Affected Dependents

No public Rust API change is expected. `chio-cli`, `chio-control-plane`,
`chio-hosted-mcp`, `chio-mcp-remote`, and conformance fixtures should continue
to compile and accept the existing HTTPS URL elicitation examples.

### Planned Improvement

Add an internal URL-required elicitation admission helper that validates each
URL-mode operation's message, URL, and elicitation ID before constructing
`KernelError::UrlElicitationsRequired`. Regressions should prove padded IDs and
non-HTTP(S) or userinfo-bearing URLs fail closed while existing valid URL
elicitations still map through.
