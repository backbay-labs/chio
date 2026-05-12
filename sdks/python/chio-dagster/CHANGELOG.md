# Changelog

All notable changes to `chio-dagster` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before forwarding them to the
  sidecar's `evaluate_tool_call` endpoint. Adopts
  `chio_adapter_base.redact.redact_args` with the chio-default policy
  (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  keyword argument on `chio_asset` / `chio_op`.
- compat: the existing `_sanitise_kwargs` helper is preserved as the
  JSON-safety pass. The new `redact_args` call runs FIRST (credential
  redaction, replaces secret-bearing fields with
  `{"omitted": True, "byte_count": N}` stubs); `_sanitise_kwargs` then
  runs SECOND (replaces non-JSON-serialisable values such as
  `pd.DataFrame` with `{"__chio_type__": ...}` markers). The two
  passes are complementary, not duplicate -- redaction protects
  secrets in receipts, sanitisation keeps the sidecar's JSON
  canonicalisation step from blowing up on rich Python objects -- and
  both apply on every call.

## [0.1.0]

- Initial release: `chio_asset` / `chio_op` decorators, partition-scoped
  capability evaluation, `ChioIOManager` for IO-level governance, and
  receipts emitted as `AssetMaterialization` metadata.
