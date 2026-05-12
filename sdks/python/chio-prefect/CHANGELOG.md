# Changelog

All notable changes to `chio-prefect` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

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
