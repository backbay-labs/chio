# Release notes: chio-adapter-base 0.2.0

This page is the docs-tree mirror of the in-package CHANGELOG entry
for `chio-adapter-base 0.2.0`. The single source of truth is
[`sdks/python/chio-adapter-base/CHANGELOG.md`](../../sdks/python/chio-adapter-base/CHANGELOG.md).
This file extracts the release-note framing into a stable docs-tree
URL so readers landing in `docs/` can find what shipped without
grepping into `sdks/python/`.

## Headline

`bind_and_redact` shape hardening + 6-axis coverage matrix.

The helper now subsumes every wire shape that was bouncing between
sibling adapters during the v0.2 batch (PRs #664-#675). The prefect
canary collapse in `chio-prefect 0.1.2` exercises the helper's API
surface against a real adapter so future shape additions land once,
in `chio-adapter-base`, rather than rippling through every sibling.

## What shipped

PR #679 is the source-of-truth commit that bundles:

1. **Helper hardening across five wire shapes** in
   `bind_and_redact`:
   - kwonly self-canonical pass
   - index-based positional aliasing with name-position collision
     re-routing (matched and unmatched names redacted independently
     rather than rejected)
   - TypeError fallback path that preserves the canonical alias
     map (closes the alias-collision data-loss path; "C1 fix")
   - `_is_pure_forwarder` no longer captures `def upload(*payload)`
     when `payload` matches a protected field
   - VAR_POSITIONAL merge-conflicts for `def fn(path, *rest, **kw)`
     shapes when a kwarg already supplies a protected slot
2. **`build_alias_map` is public** in `chio_adapter_base.redact`
   and the top-level `chio_adapter_base` namespace for adapters and
   API docs that need to inspect wrapper-name -> canonical-name
   routing. Normal adapters should still call `bind_and_redact`;
   custom routing belongs in `positional_table`.
3. **26 new regression tests (115 -> 141)** plus a 6-axis
   coverage matrix comment block at the top of
   `tests/test_bind_and_redact.py`.
4. **`positional_table` argument explicitly documented as
   REPLACES-the-default**. v0.3 documents the REPLACE semantic that
   v0.1.1 already shipped: the caller-supplied table is
   authoritative and the chio-default table is not merged in
   implicitly. No code-level behaviour change. To extend the
   chio-default with adapter-specific tools, spread it explicitly:
   `positional_table = {**DEFAULT_TOOL_POSITIONAL_NAMES, ...}`.
5. **chio-prefect 0.1.2 canary collapse** onto `bind_and_redact`
   plus a `_legacy_envelope` shim that preserves the
   prefect-specific `parameters["args"]` / `parameters["kwargs"]`
   envelope and the `__var_kw_spillover__` synthetic key.

## Migration

- Adapters that already call `bind_and_redact` and want the v0.2.0
  shape fixes: after the 0.2.0 package is published, bump the
  floor pin to `chio-adapter-base>=0.2.0,<0.3` and re-run your
  existing redaction tests. In a monorepo workspace, the same pin is
  valid when the resolver maps it to the in-repo package path.
- Adapters that only call `redact_args`: the call site is
  byte-identical across 0.1.x and 0.2.0. Stay on
  `>=0.1.0,<0.2` until you touch the wrapper next.
- Adapters that pass a custom `positional_table`: read
  [`ADAPTER-MIGRATION.md` section 5](../../sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md)
  for the spread-the-default migration recipe.

## Cross-links

- Single source of truth (in-package CHANGELOG):
  [`sdks/python/chio-adapter-base/CHANGELOG.md`](../../sdks/python/chio-adapter-base/CHANGELOG.md)
- Adapter-author migration recipe:
  [`sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md`](../../sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md)
- Pattern selection (decision tree):
  [`docs/integrations/CHOOSING_REDACTION_BOUNDARY.md`](CHOOSING_REDACTION_BOUNDARY.md)
- Integration overview and per-adapter pin matrix:
  [`docs/integrations/CHIO-ADAPTER-BASE.md`](CHIO-ADAPTER-BASE.md)
- Helper hardening + prefect canary collapse PR:
  [PR #679](https://github.com/backbay-labs/chio/pull/679)
