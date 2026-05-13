# Changelog

All notable changes to `chio-adapter-base` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-12

First non-pre-release publish. Hardens `bind_and_redact` against the
6-axis edge-case combinatoric surfaced during chio-prefect's
`_task_parameters` collapse onto the helper, and tightens the
`positional_table` contract. See `ADAPTER-MIGRATION.md` for the
adapter-author migration recipe and `docs/integrations/CHIO-ADAPTER-BASE.md`
for the higher-level rationale.

### Added
- `bind_and_redact` now handles four previously-deferred edge cells:
  - keyword-only parameters whose name collides with a protected field
    alias (e.g. `def write(*, content)` where `content` is a body
    field) are redacted in the keyword slot rather than silently
    forwarded.
  - The `TypeError` fallback path (raised by `inspect.Signature.bind`
    on duplicate-name positional + keyword) preserves the merged dict
    shape so downstream callers see the same keys they would have seen
    on a successful bind, with the secret-bearing positional value
    redacted under its derived parameter name.
  - Alias collision guard: if two positional names in the table map to
    the same parameter (mis-configured table), the helper rejects the
    table at call time rather than silently dropping the duplicate.
  - Pure `VAR_POSITIONAL` signatures (`def f(*content)`) where the
    table declares a named slot for the variadic position now redact
    each variadic value under the table's slot name.
- `DEFAULT_TOOL_POSITIONAL_NAMES` is re-exported from the top-level
  `chio_adapter_base` package so adapters do not have to grep into the
  submodule for the chio-default table.

### Changed
- **Breaking note for adapters that pass a custom `positional_table`:**
  the custom table now explicitly REPLACES the chio default rather
  than implicitly extending it. v0.1.x silently merged the caller's
  table on top of `DEFAULT_TOOL_POSITIONAL_NAMES`; v0.2.0 treats the
  caller's table as authoritative. Adapters that relied on the
  implicit extend behaviour must now explicitly merge the chio
  default into their table:

  ```python
  from chio_adapter_base.redact import DEFAULT_TOOL_POSITIONAL_NAMES

  my_table = {
      **DEFAULT_TOOL_POSITIONAL_NAMES,
      "my_custom_tool": ("path", "body"),
  }
  bind_and_redact(fn, args, kwargs, tool_name="my_custom_tool",
                  positional_table=my_table)
  ```

  See `ADAPTER-MIGRATION.md` section 5 for the migration recipe and
  test assertions to add when collapsing a local helper.

### Migration from 0.1.x
See `ADAPTER-MIGRATION.md`. Most adapters that already pin
`chio-adapter-base>=0.1.1,<0.2` and call `bind_and_redact` need no
code change beyond bumping the floor to `>=0.2.0,<0.3`. Adapters
with a local helper (the chio-prefect `_task_parameters` shape)
should collapse to `bind_and_redact` plus a thin envelope shim;
chio-prefect's PR-1 collapse is the canonical worked example.

## [0.1.1]

- feat: add `bind_and_redact` helper plus `DEFAULT_TOOL_POSITIONAL_NAMES`
  table that consolidates the bind-positional-args + redact-named-fields
  pattern that nine sibling adapters re-derived. Handles VAR_KEYWORD/
  VAR_POSITIONAL, drop_self=True for non-self receivers, merge-conflict
  resolution, and C-extension fallback. Sibling adapters can replace their
  inline `_build_redacted_parameters` / `_redact_method_call` equivalents
  with `from chio_adapter_base.redact import bind_and_redact`.
- docs: README section "Where to redact: pre-evaluation vs post-tool-call"
  documenting the chio-hermes precedent reconciliation. The 9 sibling
  adapters redact pre-evaluation (defense-in-depth, sidecar-as-untrusted);
  chio-hermes redacts post-tool-call (lets policy see real content).
  Both are valid; pick based on sidecar deployment topology.

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
