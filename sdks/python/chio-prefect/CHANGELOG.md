# Changelog

All notable changes to `chio-prefect` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before forwarding them to the Chio
  sidecar (and therefore before they land in the receipt log). Uses
  `chio_adapter_base.redact.redact_args` with the chio-default policy
  (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  keyword argument on `@chio_task` and `@chio_flow` to extend with
  adapter-specific tool names. The wrapped task body still receives
  the original, unredacted arguments; only the receipt-bound
  `parameters` payload is redacted.

## [0.1.0]

- Initial release: `@chio_task` and `@chio_flow` decorators wrapping
  Prefect's `task` / `flow` with per-task capability checks, flow-level
  scope attenuation, and Chio receipts emitted as Prefect Events.
