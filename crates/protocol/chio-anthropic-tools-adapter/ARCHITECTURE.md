# chio-anthropic-tools-adapter Architecture Notes

## Boundary

`chio-anthropic-tools-adapter` owns mediation for Anthropic Messages
`tool_use` traffic. It translates Anthropic batch and streaming payloads into
`chio-tool-call-fabric` invocations, applies the manifest-backed server-tool
gate, and lowers Chio verdicts back into Anthropic `tool_result` blocks.

The crate does not own kernel dispatch, manifest schema validation, generic
HTTP transport classification, or provider-fixture replay. Those remain in
`chio-kernel`, `chio-manifest`, `chio-provider-adapter-core`, and
`chio-provider-conformance`.

## Module Boundaries

- `lib.rs` is the public facade, adapter configuration, transport entrypoint,
  and provider identity surface.
- `adapter.rs` owns non-streaming `messages.create` lift and lower behavior.
- `streaming.rs` owns Anthropic event-stream gating and the fail-closed
  buffer-until-verdict state machine.
- `native.rs` owns Anthropic wire content-block structs and the optional
  `computer-use` server-tool catalog.
- `manifest.rs` owns the server-tool allowlist derived from
  `chio-manifest`.
- `transport.rs` pins Anthropic headers, endpoint constants, and test
  transport construction while delegating HTTP mechanics to
  `chio-provider-adapter-core`.

## Server-Tool Classification

The streaming module uses the shared provider-core SSE parser and preserves
forwarded frame bytes. Server-tool classification has one source of truth: the
`computer-use` cargo feature gate delegates server-tool recognition to the same
`chio-manifest::ServerTool::from_anthropic_wire_name` mapping used by the runtime
manifest allowlist, which maps the whole date-suffixed Anthropic server-tool
families (`bash_*`, `computer_use_*`, `text_editor_*`) to stable manifest
entries. A date-suffixed server-tool family name cannot be classified as a server
tool by the manifest gate while being missed by the feature gate, so a wire-suffix
version bump cannot turn a server tool into a regular customer tool in default
builds.

## Security And API Constraints

- Streaming tool-use frames must remain buffered until `content_block_stop`
  and a Chio verdict allows the invocation.
- Deny verdicts, evaluator errors, malformed frame order, malformed input JSON,
  and unsupported server-tool gates must fail closed before releasing buffered
  tool-use bytes.
- Allowed SSE frames should be forwarded byte-for-byte. The gate may inspect
  frame structure, but it should not rewrite provider bytes as a side effect of
  parsing.
- Server tools remain gated by both the `computer-use` feature and manifest
  `server_tools`; custom client-hosted tools must not be forced through the
  server-tool allowlist.
- The feature gate and manifest gate must use the same server-tool taxonomy.
  A version bump in Anthropic's server-tool wire suffix cannot turn the tool
  into a regular customer tool in default builds.

## Affected Dependents

`chio-provider-conformance` replays Anthropic fixtures through this adapter
when built with `fixtures-anthropic`. Server-tool classification stays internal
and preserves public APIs and fixture semantics. If dependent replay fails, the
classification contract is corrected here rather than patched in replay code.
