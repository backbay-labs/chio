# Changelog

All notable changes to `chio-dagster` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact kwargs via `chio_adapter_base.redact.redact_args`
  before the existing `_sanitise_kwargs` JSON-safety pass. Override
  via the new `redaction_policy` keyword on `chio_asset` / `chio_op`.
- design note: redact_args runs BEFORE evaluate_tool_call as defense-in-depth;
  sidecar receives only metadata for redacted fields. Tradeoff: parameter_hash
  for chio_file_write/chio_file_edit is uniform across calls. Underlying tool
  execution still receives original args.

## [0.1.0]

- Initial release: `chio_asset` / `chio_op` decorators, partition-scoped
  capability evaluation, `ChioIOManager` for IO-level governance, and
  receipts emitted as `AssetMaterialization` metadata.
