# chio-guards Architecture Notes

## Boundary

`chio-guards` owns Chio's built-in pre-invocation and post-invocation guard
implementations. The crate converts kernel `GuardContext` values into typed
action categories, evaluates policy-specific guard logic, and returns
fail-closed `Verdict` values to the hosted kernel. It should not own receipt
signing, capability validation, budget mutation, or persistent kernel state.

## Current Pain Point

Guard policy only runs after `action::extract_action` classifies a tool call.
The classifier recognizes canonical names such as `read_file`, `write_file`,
`filesystem`, and `fs`, but Chio's ACP bridge uses slash-delimited tools such as
`fs/read_text_file` and `fs/write_text_file`. Those names can currently fall
through as generic MCP tools, which means `ForbiddenPathGuard` and
`PathAllowlistGuard` never see the path-bearing action. The bridge spec already
treats filesystem-like names as filesystem category inputs, so the built-in
guard classifier must apply the same boundary before policy evaluation.

The classifier is also part of the fail-closed boundary. When a recognized
action shape presents a primary argument with the wrong JSON type, the extractor
must not skip that field and fall back to a later alias. For example, a
filesystem request with non-string `path` and string `file` is malformed, not a
safe file access to the fallback path. The same priority rule applies to command,
URL, query, patch, browser, external API, and memory aliases.

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

## Affected Dependents

The owning-crate change is internal to `chio-guards`, but it protects callers
that install `ForbiddenPathGuard` or `PathAllowlistGuard` around ACP-style
filesystem tools. `chio-acp-proxy` already enforces its own local guard path;
this slice keeps the shared built-in guard pipeline aligned for kernels that
receive the same tool names directly. No dependent API change is planned.

## Implemented Improvement

Move filesystem tool-name classification behind a shared action-extractor
boundary that understands canonical, prefix, substring, and ACP slash-delimited
filesystem names. Regression coverage proves `fs/read_text_file` reaches
`ForbiddenPathGuard`, `fs/write_text_file` reaches write allowlist policy, and
unknown non-filesystem tools still fall back to MCP classification.

Guard-boundary code now uses `extract_action_checked` so recognized action
shapes with missing required fields, mistyped priority aliases, or unparseable
network targets return a malformed-action error instead of a normal action.
Every built-in guard that depends on extracted actions denies that error before
domain-specific matching. Regression coverage includes kernel tests proving
malformed primary `path`, `command`, and `url` aliases deny instead of falling
through to benign fallback aliases.
