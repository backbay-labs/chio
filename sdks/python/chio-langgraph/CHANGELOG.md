# Changelog

All notable changes to `chio-langgraph` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact node-dispatch parameters via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar (and any HITL approval payload). Override via the new
  `redaction_policy` arg on `chio_node` and `chio_approval_node`.
- design note: `redact_args` runs BEFORE `evaluate_tool_call` (and
  before the HITL approval payload is rendered) as defense-in-depth,
  so the sidecar and the human approver receive only `byte_count` /
  `omitted` metadata for redacted fields. Tradeoffs:
  (1) `parameter_hash` for `chio_file_write` / `chio_file_edit` is
  uniform across calls and cannot distinguish content - for per-call
  forensics, combine `byte_count` with `path` and the receipt id;
  (2) capability constraints over raw byte payloads cannot be
  enforced at the sidecar in the redacted shape - enforce client-side
  before invoking the node, or thread a custom evaluation path that
  forwards raw bytes;
  (3) for HITL approval, the human approver does NOT see the raw
  body - they see `{"omitted": True, "byte_count": N}`. This is
  intentional (do not surface secret bytes in approval UIs) but
  callers who need humans to inspect content should construct a
  custom `RedactionPolicy` that skips that tool, or render the
  payload out-of-band before invoking the approval node. The
  underlying node body still receives the original args.

## [0.1.0]

- Initial release: `chio_node` wrapper, `chio_approval_node` HITL bridge,
  `ChioGraphConfig` capability wiring, and `enforce_subgraph_ceiling`
  for per-subgraph scope ceilings.
