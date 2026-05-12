# Changelog

All notable changes to `chio-langgraph` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact sensitive node-dispatch parameters before they cross into
  the Chio sidecar (and therefore before they land in the receipt log).
  Uses `chio_adapter_base.redact.redact_args` with the chio-default
  policy (`{"chio_file_write": ("content",), "chio_file_edit":
  ("patch",)}`). The redaction is applied to the parameters derived from
  LangGraph state by `_state_to_parameters` right before
  `evaluate_tool_call` and the optional approval-request payload, so
  neither the receipt nor the HITL approval prompt carries raw secret
  bytes. The wrapped node body still receives the original LangGraph
  state untouched. Pass a custom `RedactionPolicy` via the new
  `redaction_policy` constructor arg on `chio_node` and
  `chio_approval_node` to extend the default with adapter or
  workspace-specific tool names.

## [0.1.0]

- Initial release: `chio_node` wrapper, `chio_approval_node` HITL bridge,
  `ChioGraphConfig` capability wiring, and `enforce_subgraph_ceiling`
  for per-subgraph scope ceilings.
