# Changelog

All notable changes to `chio-adapter-base` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

`bind_and_redact` shape hardening + 6-axis coverage matrix. The helper
subsumes every wire shape the sibling adapters produce; the prefect
collapse in `chio-prefect 0.1.2` exercises the helper's API surface
against a real adapter so shape additions land once, in
`chio-adapter-base`.

### Added
- 26 new regression tests (115 -> 141) plus a 6-axis coverage matrix
  comment block at the top of `tests/test_bind_and_redact.py` mapping
  every cell to one or more named tests.
- 5 hypothesis property tests in
  `tests/test_bind_and_redact_properties.py`, each running 200
  examples on CI: JSON-serialisability of the redacted output, the
  helper never raises for any callable + args + kwargs combo, wire
  shape preservation across redaction, deterministic output for
  repeated identical inputs, and `byte_count` of every redacted stub
  matches the UTF-8 encoded length of the original value. Adds
  `hypothesis>=6,<7` to the dev extras.
- `build_alias_map` is exported from both `chio_adapter_base.redact`
  and the top-level `chio_adapter_base` namespace so adapters and API
  docs can inspect the wrapper-name to canonical-name routing used by
  `bind_and_redact`.

### Changed
- `bind_and_redact` keyword-only (kwonly) alias pass now treats a
  kwonly param whose name matches a protected canonical (e.g.
  `def fn(*, body)` for a policy that protects `body`) as
  self-canonical. Previously kwonly aliasing could rebind such a
  param onto a different unclaimed slot, silently corrupting the
  redaction.
- Index-based positional aliasing now applies a name-position
  collision guard. When a wrapper shape such as `def write(body,
  path)` is registered for a tool whose canonical table is
  `("path", "content")`, the helper detects that `path` lives at a
  different wrapper-index than table-index and routes the unmatched
  `body` to the next-unclaimed protected canonical (`content`)
  instead of aliasing onto the same-index unprotected slot. Matched
  and unmatched names are redacted independently.
- TypeError fallback path (arity mismatch / duplicate-keyword) now
  preserves the wrapper's canonical alias map so kwargs still redact
  under the wrapper's renamed names; previously the fallback used
  literal name matching only, which leaked when the wrapper renamed
  a protected slot.
- TypeError-fallback alias-map path now redacts each kwarg
  independently keyed by its ORIGINAL wrapper name. Two distinct
  kwargs that resolve to the same canonical (e.g. wrapper alias
  `body` -> canonical `content` AND a literal `content=` kwarg in the
  same call) used to overwrite each other in the canonical view,
  silently dropping one bucket. The fix mirrors the merge-conflict
  semantics from the variadic / overflow paths so both buckets
  round-trip with their own redaction record.
- TypeError fallback preserves the default table prefix before
  keyword-only protected aliases, so kwonly-only wrappers such as
  `def write_file(*, body)` map invalid positional calls as
  `path, body` rather than redacting the path-like first value and
  leaking later body-like values.
- TypeError fallback now treats `*name` as protected only when
  `name` is declared in the redaction policy for the current tool.
  A `*path` variadic no longer suppresses keyword-only body aliasing
  merely because `path` is a non-sensitive entry in
  `DEFAULT_TOOL_POSITIONAL_NAMES`.
- `_is_pure_forwarder` no longer treats a `def upload(*payload)`
  shape as a forwarder when `payload` matches a protected field
  for the current tool. The signature path runs instead so each
  variadic value redacts under the canonical name.
- VAR_POSITIONAL merge-conflicts for `def fn(path, *rest, **kw)`-
  shape wrappers now redact the extra positional value that collides
  with a kwarg-supplied protected slot. Extras without a table slot
  or protected collision remain raw because the helper has no safe
  field name for them.

### Documentation
- `positional_table` argument is now explicitly documented as
  REPLACES-the-default semantics; this matches the behaviour that
  already shipped in v0.1.1. No code-level behaviour change.
  Callers that want the chio-default table to coexist with a custom
  override must merge it themselves:

  ```python
  from chio_adapter_base.redact import DEFAULT_TOOL_POSITIONAL_NAMES

  my_table = {
      **DEFAULT_TOOL_POSITIONAL_NAMES,
      "my_custom_tool": ("path", "body"),
  }
  bind_and_redact(fn, args, kwargs, tool_name="my_custom_tool",
                  positional_table=my_table)
  ```

  See `ADAPTER-MIGRATION.md` section 5 for the recipe and the test
  assertions to add when collapsing a local helper.

### Notes
- Wire shape: `bind_and_redact` returns
  `(redacted_args, redacted_kwargs)` under canonical / wrapper-named
  buckets. The synthetic `__var_kw_spillover__` key for
  positional-only spillover collisions remains the prefect-local
  wire shape; chio-prefect 0.1.2's `_legacy_envelope` shim keeps it
  emitting for v0.2 compat. v0.4 will deprecate the synthetic key
  with migration guidance.

### Migration from 0.1.x
See `ADAPTER-MIGRATION.md`. Most adapters that already pin
`chio-adapter-base>=0.1.1,<0.2` and call `bind_and_redact` can bump
to `>=0.2.0,<0.3` after the 0.2.0 package is published. Adapters
with a local helper (the chio-prefect `_task_parameters` shape)
should collapse to `bind_and_redact` plus a thin envelope shim;
chio-prefect 0.1.2 (PR #679) is the canonical worked example.

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
- Seven primitives shared across adapters.
  `sanitised_env`, `harden_git_argv`, `reject_shell_argv_escape`,
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

### Package baseline
- Package layout, public API contract via type-only signatures,
  conformance hooks, and a smoke-test that asserts the public surface
  imports cleanly.
- Submodule layout over a flat namespace or a facade class.
  See `README.md` section "Submodule layout" for the design rationale.
