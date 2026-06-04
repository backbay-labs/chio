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

## Pain Points

The streaming module now uses the shared provider-core SSE parser and preserves
forwarded frame bytes, but server-tool classification is still split across two
places. `adapter.rs` carries an exact local list of beta wire names for the
`computer-use` cargo feature gate, while `chio-manifest` intentionally maps the
whole date-suffixed Anthropic server-tool families (`bash_*`,
`computer_use_*`, `text_editor_*`) to stable manifest entries. A future
date-suffixed server-tool name can therefore be classified as a server tool by
the manifest gate but missed by the feature gate.

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
when built with `fixtures-anthropic`. The intended change is internal to
server-tool classification and should preserve public APIs and fixture
semantics. If dependent replay fails, the classification contract should be
corrected here rather than patched in replay code.

## Implemented Improvement

The adapter's `computer-use` feature gate delegates server-tool recognition
to the same `chio-manifest::ServerTool::from_anthropic_wire_name` mapping used
by the runtime manifest allowlist. A regression proves a date-suffixed
server-tool family name fails closed in default builds even when the manifest
allowlists that stable server-tool entry.
