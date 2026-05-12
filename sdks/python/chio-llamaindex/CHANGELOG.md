# Changelog

All notable changes to `chio-llamaindex` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before writing them to receipts. Uses
  `chio_adapter_base.redact.redact_args` with the chio-default policy
  (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  constructor arg on `ChioFunctionTool`. The underlying function still
  sees the original (unredacted) arguments; only the parameters
  forwarded to the sidecar are redacted.

## [0.1.0]

- Initial release: `ChioFunctionTool`, `ChioQueryEngineTool`, and
  `ChioAgentRunner` for capability-scoped LlamaIndex integration.
