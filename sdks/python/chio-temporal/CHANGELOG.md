# Changelog

All notable changes to `chio-temporal` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact activity arg bodies via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar. Override via the new `redaction_policy` ctor arg on
  `ChioActivityInterceptor`. Applied in the activity layer so workflow
  determinism is unaffected. Three input shapes are now redacted:
  (1) single-dict-arg convention (in place); (2) the chio-default
  positional shapes `chio_file_write(path, content)` and
  `chio_file_edit(path, patch)`, bound by name and forwarded as a
  single dict; (3) anything else passes through verbatim.
- fix: positional `chio_file_write` / `chio_file_edit` activities
  (the natural Python signature) no longer leak the body field into
  the receipt. The interceptor now binds positional args against a
  small known-tool/arity table (`_CHIO_DEFAULT_TOOL_POSITIONAL_NAMES`)
  before redaction. Custom tools with positional secret bodies should
  pass a single dict arg or use the kwargs convention.
- design note: `redact_args` runs BEFORE `client.evaluate_tool_call`
  as defense-in-depth, so the sidecar receives only `byte_count` /
  `omitted` metadata for redacted fields. The tradeoff is that
  `parameter_hash` for `chio_file_write` / `chio_file_edit` is uniform
  across calls and cannot distinguish content. Capability constraints
  on the byte payload (e.g. `MaxLength` on `content`) cannot be
  enforced at the sidecar in the redacted shape; for those use cases
  enforce the constraint client-side before invoking the activity, or
  wrap the activity in a custom interceptor that supplies the raw
  bytes to evaluation. For per-call forensics, combine `byte_count`
  with `path` and the receipt id; the underlying activity body still
  receives the original args.
- design note: a custom `RedactionPolicy` fully REPLACES the
  chio-default `chio_file_write` / `chio_file_edit` redactions. This
  is the documented contract of `chio_adapter_base.redact.RedactionPolicy`
  (frozen mapping; no merge with the default). To extend rather than
  replace, construct your custom policy with the chio defaults
  preloaded:
  `RedactionPolicy(body_fields={**RedactionPolicy.chio_default().body_fields, "my_tool": ("body",)})`.

## [0.1.0]

- Initial release: `ChioActivityInterceptor`, `WorkflowGrant`,
  `WorkflowReceipt`, and `build_chio_worker` for Chio-governed Temporal
  workflows.
