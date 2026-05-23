# Changelog

All notable changes to `chio-ray` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- refactor: `_build_redacted_call` (used by `@chio_remote`) and
  `_redact_method_call` (used by `ChioActor`) now delegate to
  `chio_adapter_base.redact.bind_and_redact` (added in
  chio-adapter-base 0.1.1, PR #675). The local positional-name table
  and signature-walking code are removed in favour of the centralised
  helper. Wire shape and behaviour are unchanged. The actor path uses
  a `functools.partial` shim to align the receiver-less `args` shape
  with `bind_and_redact`'s signature binding (``drop_self`` expects
  the receiver to live at ``args[0]``, which the wrapper has already
  stripped). Dependency bumped to `chio-adapter-base>=0.1.1,<0.2`.
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
