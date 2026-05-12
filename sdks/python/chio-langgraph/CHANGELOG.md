# Changelog

All notable changes to `chio-langgraph` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact node-dispatch parameters via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar (and any HITL approval payload). Override via the new
  `redaction_policy` arg on `chio_node` and `chio_approval_node`.

## [0.1.0]

- Initial release: `chio_node` wrapper, `chio_approval_node` HITL bridge,
  `ChioGraphConfig` capability wiring, and `enforce_subgraph_ceiling`
  for per-subgraph scope ceilings.
