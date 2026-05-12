# Changelog

All notable changes to `chio-airflow` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: `@chio_task` redacts kwarg bodies via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar. Override via the new `redaction_policy` arg.
- fix: positional invocations
  (`write_file("/tmp/x", "PROD_SECRET")`) are bound to their parameter
  names with `inspect.signature.bind_partial` before redaction, so
  positional `content` / `patch` args no longer bypass the redactor and
  leak into receipts. The forwarded payload now carries bound args under
  `kwargs` (with `args == []`) when the wrapped function has a fixed
  signature; `*args` / `**kwargs` wrappers fall back to the prior shape.
- design note: `redact_args` runs BEFORE `evaluate_tool_call` as
  defense-in-depth, so the sidecar receives only `byte_count` /
  `omitted` metadata for redacted fields. The tradeoff is that
  `parameter_hash` for `chio_file_write` / `chio_file_edit` is uniform
  across calls and cannot distinguish content. For per-call forensics,
  combine `byte_count` with the path and the receipt id; the underlying
  tool execution still receives the original args.

## [0.1.0]

- Initial release: `ChioOperator` wrapper, TaskFlow `@chio_task`
  decorator, and DAG listener that push receipt ids into XCom.
