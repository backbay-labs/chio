# Changelog

All notable changes to `chio-temporal` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact sensitive activity argument bodies before forwarding them
  to the Chio sidecar (and into the per-step receipt). Uses
  `chio_adapter_base.redact.redact_args` with the chio-default policy
  (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  constructor arg on `ChioActivityInterceptor`. Redaction is applied in
  the activity-layer interceptor (not inside the workflow) so Temporal
  workflow determinism rules are unaffected; the underlying activity
  function still receives its original (unredacted) arguments.
  Redaction targets the keyword-style mapping in the activity's first
  positional argument when it is a dict; activities that pass purely
  positional args are passed through unchanged.

## [0.1.0]

- Initial release: `ChioActivityInterceptor`, `WorkflowGrant`,
  `WorkflowReceipt`, and `build_chio_worker` for Chio-governed Temporal
  workflows.
