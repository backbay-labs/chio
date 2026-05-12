# Changelog

All notable changes to `chio-adapter-base` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 2: ported the seven primitives from chio-hermes into the new
  package. `sanitised_env`, `harden_git_argv`, `reject_shell_argv_escape`,
  `resolve_within`, and `BoundedSubprocess` (plus async `arun`) live in
  `chio_adapter_base.security`. `ReceiptBuffer`, `append_jsonl`, and
  `canonical_dumps` live in `chio_adapter_base.receipts`. `redact_args`
  and the table-driven `RedactArgs` callable live in
  `chio_adapter_base.redact`. `forbidden_path_filter` plus the
  format-aware wrappers `filter_directory_entries`, `filter_diff_output`,
  and `filter_status_output` live in `chio_adapter_base.filters`.
- `ChioPathEscapeError` (subclass of `PermissionError`) raised by
  `reject_shell_argv_escape` so adapters can branch on workspace
  escape vs other permission denials.
- `chio_adapter_base.conformance` now ships `ConformanceFixture` plus
  reusable assertions (`assert_redacts_secrets`, `assert_receipts_fifo`,
  `assert_denial_count_increments`, `assert_forbidden_path_filter_partitions`)
  and an `adapter_base_fixture` pytest fixture sibling adapters can
  pull in via `pytest_plugins = ["chio_adapter_base.conformance"]`.
- 88 behavioural tests across `test_security.py`, `test_receipts.py`,
  `test_redact.py`, `test_filters.py`, `test_conformance.py`, and
  the existing `test_imports.py` smoke test.

### Changed
- mypy is now strict (`strict = true` in `pyproject.toml`); every
  public signature has explicit type hints.

### Phase 1 (scaffold) baseline
- Package layout, public API contract via type-only signatures,
  conformance hooks, and a smoke-test that asserts the public surface
  imports cleanly.
- Submodule layout chosen over flat namespace and over a facade class.
  See `.planning/chio-adapter-base/PLAN.md` section 3 for the design
  rationale.
