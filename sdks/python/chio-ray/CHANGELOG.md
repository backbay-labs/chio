# Changelog

All notable changes to `chio-ray` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact kwargs via `chio_adapter_base.redact.redact_args`
  before forwarding to the sidecar. Override via the new
  `redaction_policy` keyword on `chio_remote(...)` and
  `ChioActor.__init__(...)`. Note: this only governs receipt-log
  parameters; Ray's object store still holds the pickled originals.
- design note: `redact_args` runs BEFORE `evaluate_tool_call` as
  defense-in-depth, so the sidecar receives only `byte_count` /
  `omitted` metadata for redacted fields. The tradeoffs:
  (1) `parameter_hash` for `chio_file_write` / `chio_file_edit` is
  uniform across calls and cannot distinguish content - for per-call
  forensics, combine `byte_count` with `path` and the receipt id;
  (2) capability constraints on raw byte payloads (e.g. `MaxLength`
  on `content`, `MaxArgsSize`) cannot be enforced at the sidecar in
  the redacted shape - enforce client-side before invoking the remote
  function, or wrap evaluation in a custom path that forwards the
  raw bytes. The underlying remote function still receives the
  original args.

## [0.1.0]

- Initial release: `@chio_remote` decorator and `ChioActor` base class
  with standing capability grants.
