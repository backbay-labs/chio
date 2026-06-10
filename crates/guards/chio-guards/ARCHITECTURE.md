# chio-guards Architecture Notes

## Boundary

`chio-guards` owns Chio's built-in pre-invocation and post-invocation guard
implementations. The crate converts kernel `GuardContext` values into typed
action categories, evaluates policy-specific guard logic, and returns
fail-closed `Verdict` values to the hosted kernel. It should not own receipt
signing, capability validation, budget mutation, or persistent kernel state.

## Action Classification Boundary

Guard policy runs after `action::extract_action` classifies a tool call. The
classifier recognizes canonical names such as `read_file`, `write_file`,
`filesystem`, and `fs`, and the slash-delimited ACP bridge tools such as
`fs/read_text_file` and `fs/write_text_file`. Filesystem-shaped names that carry
a `path` argument reach `ForbiddenPathGuard` and `PathAllowlistGuard` instead of
falling through as generic MCP tools.

The classifier is part of the fail-closed boundary. When a recognized action
shape presents a primary argument with the wrong JSON type, the extractor does
not skip that field and fall back to a later alias. A filesystem request with
non-string `path` and string `file` is malformed, not a safe file access to the
fallback path. The same priority rule applies to command, URL, query, patch,
browser, external API, and memory aliases.

## Security And API Constraints

- Guard evaluation must remain fail-closed for malformed guard configuration.
- Public guard constructors, config structs, result structs, and re-exports
  must remain compatible.
- Existing canonical tool names must keep their current action classification.
- Slash-delimited and prefix filesystem tools must not bypass path guards when
  they carry a `path` argument.
- Read-like filesystem tools should remain read actions, write/delete/create
  tools should use write policy, and patch tools should still use patch policy.
- Malformed recognized actions must be denied by every guard that depends on
  `extract_action`, even when that guard is installed without the default
  pipeline.
- Unknown tools without filesystem shape must continue to fall back to
  `McpTool` so `McpToolGuard` allow/block lists still apply.

## Dependents

The classification boundary protects callers that install `ForbiddenPathGuard`
or `PathAllowlistGuard` around ACP-style filesystem tools. `chio-acp-proxy`
enforces its own local guard path; the shared built-in guard pipeline applies
the same classification for kernels that receive the tool names directly.

## Malformed-Action Handling

Filesystem tool-name classification sits behind a shared action-extractor
boundary that understands canonical, prefix, substring, and ACP slash-delimited
filesystem names: `fs/read_text_file` reaches `ForbiddenPathGuard`,
`fs/write_text_file` reaches write allowlist policy, and unknown non-filesystem
tools fall back to MCP classification.

Guard-boundary code uses `extract_action_checked`, so recognized action shapes
with missing required fields, mistyped priority aliases, or unparseable network
targets return a malformed-action error instead of a normal action. Every
built-in guard that depends on extracted actions denies that error before
domain-specific matching. Malformed primary `path`, `command`, and `url` aliases
deny rather than falling through to benign fallback aliases.

## Verification Focus

Regression coverage proves the classification boundary holds end to end:
`fs/read_text_file` reaches `ForbiddenPathGuard`, `fs/write_text_file` reaches
write allowlist policy, and unknown non-filesystem tools still fall back to
`McpTool`. Kernel-level tests assert that malformed primary `path`, `command`,
and `url` aliases deny rather than falling through to a benign fallback, so a
mistyped action shape cannot be laundered into a safe one.
