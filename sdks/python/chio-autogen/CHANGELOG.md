# Changelog

All notable changes to `chio-autogen` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- chore: bump `chio-adapter-base` dependency to `>=0.1.1,<0.2` so the
  centralised `bind_and_redact` helper and
  `DEFAULT_TOOL_POSITIONAL_NAMES` registry (added in chio-adapter-base
  0.1.1, PR #675) are available downstream. No source change is needed
  here because `chio-autogen` already redacts via dict-keyed kwargs and
  has no positional-binding helper to consolidate.
- feat: redact tool argument bodies via `chio_adapter_base.redact.redact_args`
  before forwarding them to the sidecar. Override via the new
  `redaction_policy` ctor arg on `ChioFunctionRegistry`.
- design note: `redact_args` runs BEFORE `evaluate_tool_call` as
  defense-in-depth, so the sidecar receives only `byte_count` /
  `omitted` metadata for redacted fields. The tradeoff: `parameter_hash`
  for `chio_file_write` / `chio_file_edit` is uniform across calls and
  cannot distinguish content. Capability constraints on the raw byte
  payload (e.g. `MaxLength` on `content`) cannot be enforced at the
  sidecar in the redacted shape; for those use cases enforce client-side
  before invoking the tool. For per-call forensics, combine `byte_count`
  with `path` and the receipt id; the underlying tool execution still
  receives the original args.

## [0.1.0]

- Initial release: `ChioFunctionRegistry`, `ChioGroupChat` /
  `ChioGroupChatManager`, and `register_nested_chats_with_attenuation`
  for capability-scoped AutoGen integration.
