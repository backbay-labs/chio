# Adapter migration guide: chio-adapter-base 0.1.x to 0.2.0

This guide is for authors of Chio Python adapters
(`chio-langchain`, `chio-llamaindex`, `chio-crewai`, `chio-iac`,
`chio-airflow`, `chio-ray`, `chio-temporal`, `chio-langgraph`,
`chio-dagster`, `chio-prefect`, `chio-autogen`, `chio-streaming`,
plus any out-of-tree adapter pinning
`chio-adapter-base>=0.1.0,<0.2`).

The companion `CHANGELOG.md` carries the canonical changelog
entries; this file is the migration recipe for adapter authors who
are bumping the floor from `0.1.x` to `0.2.0`.

## 1. What changed in 0.2.0

`bind_and_redact` is hardened against the wire shapes that
chio-prefect's `_task_parameters` collapse exposes:

1. **Keyword-only self-canonical pass**: a kwonly param whose name
   matches a protected canonical (e.g. `def fn(*, body)` for a
   policy that protects `body`) is now treated as self-canonical;
   previously kwonly aliasing could rebind it onto a different
   unclaimed slot and silently corrupt the redaction.
2. **Index-based positional aliasing with name-position collision
   guard**: for a wrapper such as `def write(body, path)` against a
   tool table `("path", "content")`, the helper detects the
   wrapper-index vs table-index collision on `path` and routes the
   unmatched `body` to the next-unclaimed protected canonical
   (`content`) instead of aliasing onto the same-index unprotected
   slot. Matched and unmatched names are redacted independently.
3. **TypeError fallback preserves the canonical alias map** so
   kwargs still redact under wrapper-renamed names when
   `inspect.Signature.bind` raises, closing the alias-collision
   data-loss path.
4. **`_is_pure_forwarder` no longer captures `def upload(*payload)`**
   when `payload` matches a protected field; the signature path runs
   instead so each variadic value redacts under the canonical name.
5. **VAR_POSITIONAL merge-conflicts for `def fn(path, *rest, **kw)`**
   now redact the extra positional value that collides with a
   kwarg-supplied protected slot. Extras that have no table slot or protected
   collision remain raw because the helper has no safe field name for
   them.

`build_alias_map` is now public in `chio_adapter_base.redact` and
the top-level `chio_adapter_base` namespace for adapters and API
docs that need to inspect wrapper-name -> canonical-name routing.
Normal adapters should still call `bind_and_redact`; custom routing
belongs in `positional_table`, with `build_alias_map` used only for
diagnostics or adapter-local tests.

The `positional_table` argument's contract is also explicitly
documented as REPLACES-the-default semantics (see Section 5);
this matches the behaviour that already shipped in v0.1.1.

## 2. If your adapter calls `bind_and_redact`

The wire shape is unchanged: `bind_and_redact` still returns
`(redacted_args, redacted_kwargs)` and positional values stay
positional, keyword values stay keyword. The four edge-case fixes
are additive (cells that previously leaked are now redacted; cells
that already worked still work the same way).

What you need to do:

1. **Bump the floor pin** in your adapter's `pyproject.toml`:

   ```toml
   dependencies = [
       "chio-adapter-base>=0.2.0,<0.3",
   ]
   ```

   Use this pin once the 0.2.0 package is published or when your
   workspace resolves `chio-adapter-base` from the in-repo path.
   chio-prefect already bumps to this floor in its 0.1.2 release.
   Other adapters that only call `redact_args`
   and have no exposure to the v0.2.0 `bind_and_redact` edge cells
   can stay on `chio-adapter-base>=0.1.0,<0.2` until they touch
   their wrappers next; the `redact_args` call sites are
   byte-identical across 0.1.x and 0.2.0.

2. **If you pass a custom `positional_table`,** read Section 5 of
   this guide. The replace semantic is not new, but it is the
   easiest contract to misunderstand during migration.

3. **Re-run your existing redaction tests against the new floor.**
   They should still pass byte-identical. If a test starts failing
   only after the floor bump, it is most likely the
   replaces-vs-extends change in Section 5.

4. **(Optional, recommended) add a regression test for the new
   edge cells** if your adapter wraps any of these signature
   shapes:
   - `def fn(*, body)` (kwonly param whose name matches a
     protected canonical).
   - `def write(body, path)` against a tool table that orders
     them differently (`("path", "content")`).
   - Custom tools that previously triggered
     `inspect.Signature.bind` to raise `TypeError` (arity
     mismatch / duplicate-name positional + keyword).
   - `def upload(*payload)` where `payload` matches a protected
     field for the current tool.
   - `def fn(path, *rest, **kw)` where a kwarg has already
     supplied a protected slot.

   Section 6 lists the assertion shape to use.

## 3. If your adapter calls `redact_args` directly

`redact_args(tool_name, args, *, policy=None)` is unchanged in
0.2.0. The signature, return type, and stub shape
(`{"omitted": True, "byte_count": N}`) are byte-identical to
0.1.x.

When to migrate to `bind_and_redact`:

- Your wrapper sees the tool call as `(*args, **kwargs)` rather
  than as a pre-named `dict` (i.e. you have to construct the
  named-args dict yourself before calling `redact_args`). Building
  that dict by hand is exactly what `bind_and_redact` automates,
  and getting it right against the 6-axis matrix
  (`fixed`/`fixed+kwonly`/`fixed+VAR_POSITIONAL`/`fixed+VAR_KEYWORD`/
  pure `VAR_POSITIONAL`/pure `VAR_KEYWORD`) is what
  `bind_and_redact` is for.
- Your wrapper currently has a local helper named
  `_build_redacted_parameters`, `_redact_method_call`,
  `_task_parameters`, or similar. See Section 4.

When NOT to migrate:

- Your wrapper already sees a pre-named dict of args (the LangChain
  `_arun(**kwargs)` / `_run(**kwargs)` surface, the LlamaIndex
  `BaseTool.acall(**kwargs)` surface, the CrewAI `BaseTool._run(**kwargs)`
  surface). These are kwargs-only by design; `bind_and_redact`
  would do nothing more than `redact_args` does. Stay on
  `redact_args`.

## 4. If your adapter has a local helper

The canonical example is chio-prefect's `_task_parameters`
(`sdks/python/chio-prefect/src/chio_prefect/decorators.py`). It is a
thin envelope shim over `bind_and_redact`: it preserves the
prefect-specific `parameters["args"]` / `parameters["kwargs"]`
envelope plus the `__var_kw_spillover__` synthetic-key shape while
delegating the shared binding and redaction logic to `bind_and_redact`.

Recipe:

1. **Identify the helper's responsibilities.** A typical local
   helper does three things: (a) walks the wrapped callable's
   signature to map positional values to parameter names,
   (b) calls `redact_args` over the named view, and (c) wraps the
   result in the adapter's wire-shape envelope (e.g.
   `{"args": [...], "kwargs": {...}}`).

2. **Replace (a) and (b) with `bind_and_redact`.** It already
   handles every documented signature shape, including the edge
   cells fixed in 0.2.0. Pass the adapter's `tool_name`,
   the `RedactionPolicy` (build a custom one if you have
   adapter-specific protected fields), and `drop_self=True` if
   the wrapper sees a method receiver in `args[0]`.

3. **Keep (c) as a thin envelope shim.** If your adapter ships
   a wire shape that downstream consumers (dashboards, receipt
   queries) already depend on, do not change that shape; the
   shim just rewraps `bind_and_redact`'s
   `(redacted_args, redacted_kwargs)` into your envelope.

4. **Delete the helper's tests for cells `bind_and_redact` now
   covers.** Keep tests that exercise your envelope shim
   specifically (e.g. "the synthetic spillover key still appears
   in the wire shape"). The shared-helper coverage lives in
   `chio_adapter_base/tests/test_bind_and_redact.py`.

5. **Add one parity test** that asserts your shim plus
   `bind_and_redact` produces the byte-identical wire shape your
   old helper produced for at least one representative tool call
   per signature shape your adapter wraps.

The worked example lives in
`sdks/python/chio-prefect/src/chio_prefect/decorators.py`'s
`_task_parameters`, which preserves the prefect-specific
`parameters["args"]` / `parameters["kwargs"]` envelope plus the
`__var_kw_spillover__` synthetic key against `bind_and_redact`'s
`(redacted_args, redacted_kwargs)` return shape.

## 5. Custom `positional_table` semantic clarification (REPLACES)

A caller-supplied `positional_table` REPLACES the default: the
chio-default table is not merged in implicitly.

No code migration is required. Be aware that a custom
`positional_table` fully replaces `DEFAULT_TOOL_POSITIONAL_NAMES`
rather than extending it.
If your adapter declares custom tools and you also want the
chio-default entries (`chio_file_write`, `chio_file_edit`) to keep
working, merge the default in explicitly:

```python
from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    bind_and_redact,
)

MY_TABLE = {
    **DEFAULT_TOOL_POSITIONAL_NAMES,
    "my_custom_tool": ("path", "body"),
}

redacted_args, redacted_kwargs = bind_and_redact(
    fn,
    args,
    kwargs,
    tool_name="my_custom_tool",
    positional_table=MY_TABLE,
)
```

If your adapter intentionally overrides the chio-default ordering
for `chio_file_write` or `chio_file_edit`, the `replace` semantic
is what you wanted; document the override locally and do nothing
else.

If you want to audit existing call sites, grep for
`positional_table=` in your adapter and inspect each call's
table contents:

```bash
grep -rn 'positional_table=' src/
```

For each hit, if the table contains a chio-default tool name
(`chio_file_write`, `chio_file_edit`), the override is
intentional. If it contains only adapter-specific tool names and
you also want the chio-default entries to apply for those tools,
add the spread shown above.

## 6. Testing your migration

Per-cell assertions to add to your adapter's redaction test
suite. Each one is a single test function; the assertion shape
is the same across all of them:

1. **Path-and-body wire shape**: assert that for a
   `chio_file_write`-shaped call, the rebuilt `args` carries the
   path verbatim and `kwargs` (or the second positional slot)
   carries the omitted-stub.

   ```python
   redacted_args, redacted_kwargs = bind_and_redact(
       fn=my_write,
       args=("/tmp/x", "SECRET"),
       kwargs={},
       tool_name="chio_file_write",
   )
   assert redacted_args[0] == "/tmp/x"
   assert redacted_args[1] == {
       "omitted": True,
       "byte_count": 6,  # len("SECRET".encode("utf-8"))
   }
   ```

2. **Keyword-only self-canonical** (new in 0.2.0): assert that
   `def fn(*, body)` against a policy that protects `body`
   redacts the `body` kwarg in place rather than re-binding it
   onto a different unclaimed slot.

3. **Index-collision re-routing** (new in 0.2.0): assert that
   for `def write(body, path)` against a tool whose canonical
   table is `("path", "content")`, the wrapper's `body`
   positional value redacts under `content` (the next-unclaimed
   protected canonical) while `path` is preserved.

4. **TypeError fallback canonical alias preservation** (new in
   0.2.0): assert that a duplicate-name positional + kwarg call
   that triggers the `TypeError` fallback still produces a
   redacted output that maps wrapper-renamed kwargs back onto
   their canonical protected slots.

5. **`_is_pure_forwarder` excludes protected variadic name**
   (new in 0.2.0): assert that `def upload(*payload)` against a
   policy that protects `payload` redacts each variadic value
   (does NOT pass-through as a forwarder).

6. **VAR_POSITIONAL merge-conflict with kwarg-supplied slot** (new
   in 0.2.0): for `def fn(path, *rest, **kw)`, assert that when
   `kw` already supplies a protected slot (e.g. `body=`), the
   colliding variadic extra redacts under the canonical protected
   slot. Do not
   assert that arbitrary extras beyond known slots are redacted.

7. **Custom `positional_table` replace semantic** (new in
   0.2.0): assert that a custom table NOT containing
   `chio_file_write` does not redact `chio_file_write` calls
   under that table (proves replace, not extend, is in
   effect).

8. **Byte-count invariant**: for every redacted field, assert
   `byte_count == len(value.encode("utf-8"))` (or
   `len(value)` for `bytes` / `bytearray`).

If your adapter has a parity shim wrapping `bind_and_redact`
back into its previous envelope shape, also assert that the shim's
output is byte-identical to a golden snapshot of that earlier output for
at least one call per signature shape your adapter wraps.
