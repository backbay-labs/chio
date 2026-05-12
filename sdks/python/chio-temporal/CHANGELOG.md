# Changelog

All notable changes to `chio-temporal` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact activity arg bodies via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar. Override via the new `redaction_policy` ctor arg on
  `ChioActivityInterceptor`. Applied in the activity layer so workflow
  determinism is unaffected. Only fires for the single-dict-arg
  convention; purely positional args pass through unchanged.

## [0.1.0]

- Initial release: `ChioActivityInterceptor`, `WorkflowGrant`,
  `WorkflowReceipt`, and `build_chio_worker` for Chio-governed Temporal
  workflows.
