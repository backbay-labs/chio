# Changelog

All notable changes to `chio-adapter-base` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

`bind_and_redact` shape hardening + 6-axis coverage matrix. The
helper now subsumes every wire shape that was bouncing between
sibling adapters during the v0.2 batch (PRs #664-#675); the prefect
canary collapse in `chio-prefect 0.1.2` exercises the helper's API
surface against a real adapter so future shape additions land once,
in `chio-adapter-base`. See `ADAPTER-MIGRATION.md` for the
adapter-author migration recipe and
`docs/integrations/CHIO-ADAPTER-BASE.md` for the higher-level
rationale.

> Note: the canonical changelog narrative for the helper hardening
> lives in PR #679's commit on this same file; this entry is the
> docs-PR view of the same release. If the two ever drift, treat
> the in-package CHANGELOG that landed via PR #679 as authoritative.

### Added
- 26 new regression tests (115 -> 141) plus a 6-axis coverage matrix
  comment block at the top of `tests/test_bind_and_redact.py`
  mapping every cell to one or more named tests.

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
  different wrapper-index than table-index and routes the
  unmatched `body` to the next-unclaimed protected canonical
  (`content`) instead of aliasing onto the same-index unprotected
  slot. The collision is detected and re-routed; matched and
  unmatched names are redacted independently rather than being
  rejected.
- `TypeError` fallback path (raised by `inspect.Signature.bind` on
  arity mismatch / duplicate-name positional + keyword) now
  preserves the wrapper's canonical alias map so kwargs still
  redact under the wrapper's renamed names. Previously the
  fallback used literal name matching only, which leaked when the
  wrapper renamed a protected slot. Closes the alias-collision
  data-loss path documented in PR #679 (the "C1 fix").
- `_is_pure_forwarder` no longer treats a `def upload(*payload)`
  shape as a forwarder when `payload` matches a protected field
  for the current tool. The signature path runs instead so each
  variadic value redacts under the canonical name.
- VAR_POSITIONAL extras for `def fn(path, *rest, **kw)`-shape
  wrappers now redact under the canonical protected slot when a
  kwarg has already supplied that slot. This is the
  merge-conflict semantics for the variadic case (closes deferred
  IDs 3229566280 and 3229515822).

### Documentation
- `positional_table` argument is now explicitly documented as
  REPLACES-the-default semantics; this matches the behaviour that
  already shipped in v0.1.1 (the per-tool override was always read
  as REPLACE in the v0.1.x helper). No code-level behaviour change.
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
  `(redacted_args, redacted_kwargs)` under canonical /
  wrapper-named buckets. The synthetic `__var_kw_spillover__` key
  for positional-only spillover collisions remains the
  prefect-local wire shape; chio-prefect 0.1.2's `_legacy_envelope`
  shim keeps it emitting for v0.2 compat. v0.4 will deprecate the
  synthetic key with a one-release migration window.

### Migration from 0.1.x
See `ADAPTER-MIGRATION.md`. Most adapters that already pin
`chio-adapter-base>=0.1.1,<0.2` and call `bind_and_redact` need no
code change beyond bumping the floor to `>=0.2.0,<0.3`. Adapters
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
