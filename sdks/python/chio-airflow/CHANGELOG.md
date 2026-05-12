# Changelog

All notable changes to `chio-airflow` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- refactor: `_build_redacted_parameters` now delegates to
  `chio_adapter_base.redact.bind_and_redact` (added in
  chio-adapter-base 0.1.1). Wire shape, fallback paths, and behaviour
  are unchanged; the local positional-name table and signature-walking
  code are deleted in favour of the centralised helper. Dependency
  bumped to `chio-adapter-base>=0.1.1,<0.2`.
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
- design note: redaction is wired only on the TaskFlow `@chio_task`
  path. `ChioOperator` records DAG / task / capability context fields
  in the sidecar payload rather than per-tool argument bodies because
  the wrapper does not introspect the inner operator's parameters; the
  inner operator's templated fields and `op_kwargs` are owned by the
  caller and remain outside the per-call redaction surface here.
- v0.2 follow-up (deferred primitives): `chio-adapter-base` is also
  missing `sanitised_env`, `bounded_subprocess`, `harden_git_argv`, and
  `shell_argv_escape_check` per the cross-adapter audit. Once those
  land, downstream Airflow operators that shell out should adopt them.

## [0.1.0]

- Initial release: `ChioOperator` wrapper, TaskFlow `@chio_task`
  decorator, and DAG listener that push receipt ids into XCom.
