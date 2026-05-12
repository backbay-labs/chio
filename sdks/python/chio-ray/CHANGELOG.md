# Changelog

All notable changes to `chio-ray` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before forwarding them to the
  sidecar's `evaluate_tool_call` payload. Both `@chio_remote` (Ray
  task wrapper) and `ChioActor.requires` (Ray actor method gate) now
  call `chio_adapter_base.redact.redact_args` against the per-call
  `kwargs` using the resolved `tool_name`. Default policy is
  `RedactionPolicy.chio_default()` (redacts `chio_file_write.content`
  and `chio_file_edit.patch`); pass a custom `RedactionPolicy` via the
  new `redaction_policy` keyword on `chio_remote(...)` and on
  `ChioActor.__init__(...)` to extend the mapping with adapter-specific
  tool names.
- note: Ray's object store may still contain the original (unredacted)
  argument values because Ray pickles task arguments before they reach
  the wrapper that performs redaction. The redaction guarantee
  documented here applies only to the parameters embedded in the Chio
  receipt log; defending the object store itself is a follow-up
  (see audit `M` for `receipt_buffer`).

## [0.1.0]

- Initial release: `@chio_remote` decorator and `ChioActor` base class
  with standing capability grants.
