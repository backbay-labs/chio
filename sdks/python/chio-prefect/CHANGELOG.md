# Changelog

All notable changes to `chio-prefect` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2]

- refactor: replace the local `_task_parameters` body (and its
  `_forwarding_table_or_passthrough` helper) with a thin shim around
  `chio_adapter_base.redact.bind_and_redact`. The new
  `_legacy_envelope` shim does two prefect-specific jobs: wraps the
  helper's `(redacted_args, redacted_kwargs)` return into prefect's
  `{"args": [...], "kwargs": {...}}` sidecar payload envelope, and
  re-emits the synthetic `<name>__var_kw_spillover__` keys for
  positional-only-vs-kwarg spillover collisions to preserve the v0.2
  wire shape. v0.4 will deprecate the synthetic-key emission with a
  migration guidance. Dependency bumped to
  `chio-adapter-base>=0.2.0,<0.3`.
- fix: the bind_and_redact helper hardening landed in
  `chio-adapter-base 0.2.0` covers every prefect-side edge case the
  v0.2 batch surfaced (variadic-named-after-protected, pure-forwarder
  kwarg precedence, alias-rename redaction, TypeError fallback
  alias-map preservation). All 41 existing tests pass byte-identical
  against the new shim.

## [0.1.1]

- refactor: the local `_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES` literal is
  removed; the module now binds the alias to
  `chio_adapter_base.redact.DEFAULT_TOOL_POSITIONAL_NAMES` (added in
  chio-adapter-base 0.1.1, PR #675) so the chio-default registry stays
  in one place across the adapter family. The body of `_task_parameters`
  retains its bespoke signature-walking implementation because it
  encodes two prefect-specific contracts that
  `chio_adapter_base.redact.bind_and_redact` does not currently
  express: VAR_POSITIONAL extras are redacted via the table when the
  slot index has a declared name (covers `def fn(path, *args)` shapes,
  see `TestFixedPositionalWithVarPositional`), and VAR_KEYWORD
  spillover entries that collide with a fixed name are routed to a
  synthetic `<name>__var_kw_spillover__` key (see
  `TestPositionalOnlyVarKeywordSpillover`). Dependency bumped to
  `chio-adapter-base>=0.1.1,<0.2`.
- feat: redact tool argument bodies via
  `chio_adapter_base.redact.redact_args` before forwarding to the Chio
  sidecar. Default policy covers `chio_file_write.content` and
  `chio_file_edit.patch`. Pass a custom `RedactionPolicy` via the new
  `redaction_policy` keyword on `@chio_task` / `@chio_flow` (a custom
  policy fully replaces the default). The wrapped task body still
  receives the original, unredacted arguments.
- fix: positional invocations
  (`write_file("/tmp/x", "PROD_SECRET")`) are bound to their parameter
  names with `inspect.signature.bind_partial` before redaction, so
  positional `content` / `patch` args no longer bypass the redactor and
  leak into receipts. The forwarded payload now carries bound args under
  `kwargs` (with `args == []`) when the wrapped function has a fixed
  signature; `*args` / `**kwargs` wrappers fall back to the prior shape.
  This supersedes the earlier "kwargs-only redaction" decision.
- design note: `redact_args` runs BEFORE `evaluate_tool_call` as
  defense-in-depth, so the sidecar receives only `byte_count` /
  `omitted` metadata for redacted fields. The tradeoff is that
  `parameter_hash` for `chio_file_write` / `chio_file_edit` is uniform
  across calls and cannot distinguish content. For per-call forensics,
  combine `byte_count` with the path and the receipt id; the underlying
  task body still receives the original args.

## [0.1.0]

- Initial release: `@chio_task` and `@chio_flow` decorators wrapping
  Prefect's `task` / `flow` with per-task capability checks, flow-level
  scope attenuation, and Chio receipts emitted as Prefect Events.
