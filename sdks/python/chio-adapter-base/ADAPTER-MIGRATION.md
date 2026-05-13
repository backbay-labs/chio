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

`bind_and_redact` is hardened against four edge cells that
chio-prefect's `_task_parameters` collapse exposed: keyword-only
protected aliases, `TypeError` fallback shape preservation, an
alias-collision guard against mis-configured `positional_table`
inputs, and pure `VAR_POSITIONAL` signatures with a named table
slot. The chio-default positional-name table
(`DEFAULT_TOOL_POSITIONAL_NAMES`) is now re-exported from the
top-level package. The `positional_table` argument's contract has
also changed: a caller-supplied table now REPLACES the chio default
rather than implicitly extending it (see Section 5).

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

2. **If you pass a custom `positional_table`,** read Section 5 of
   this guide. The semantic change there is the only behaviour
   change a caller can hit without intentionally exercising one of
   the new edge cells.

3. **Re-run your existing redaction tests against the new floor.**
   They should still pass byte-identical. If a test starts failing
   only after the floor bump, it is most likely the
   replaces-vs-extends change in Section 5.

4. **(Optional, recommended) add a regression test for the new
   edge cells** if your adapter wraps any of these signature
   shapes:
   - `def f(*, content)` (keyword-only protected alias).
   - Custom tools that previously triggered `bind_partial` to
     raise `TypeError` for a duplicate-name positional + keyword.
   - `def f(*content)` (pure `VAR_POSITIONAL` with a named slot
     in your `positional_table`).

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
(originally at
`sdks/python/chio-prefect/src/chio_prefect/decorators.py:486`).
The collapse onto `bind_and_redact` plus a thin envelope shim is
covered by PR-1 of the v0.3 release; the resulting shim is
~20 lines and preserves the prefect-specific
`parameters["args"]` / `parameters["kwargs"]` envelope plus the
`__var_kw_spillover__` synthetic-key shape so prefect's existing
41 redaction tests pass byte-identical.

Recipe:

1. **Identify the helper's responsibilities.** A typical local
   helper does three things: (a) walks the wrapped callable's
   signature to map positional values to parameter names,
   (b) calls `redact_args` over the named view, and (c) wraps the
   result in the adapter's wire-shape envelope (e.g.
   `{"args": [...], "kwargs": {...}}`).

2. **Replace (a) and (b) with `bind_and_redact`.** It already
   handles every documented signature shape, including the four
   edge cells fixed in 0.2.0. Pass the adapter's `tool_name`,
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

The chio-prefect collapse will land as PR-1 of the
`chio-adapter-base` v0.3 release; once merged, link to the
relevant commit here for the worked example. (TODO: PR-1 commit
SHA and chio-prefect link, fill in once PR-1 merges.)

## 5. Custom `positional_table` semantic change: extends -> replaces

This is the one behaviour change in 0.2.0 that a passive caller
can hit. v0.1.x silently merged the caller's `positional_table`
on top of `DEFAULT_TOOL_POSITIONAL_NAMES`. v0.2.0 treats the
caller's table as authoritative; the chio default is no longer
merged in implicitly.

Why the change: implicit extension hides the contract. An adapter
that wants to redefine the positional ordering for `chio_file_write`
(for example, exposing `(content, path)` instead of `(path, content)`
because the wrapper's signature is in that order) cannot do so
without `replace`. Implicit extend also makes it harder to audit
what an adapter actually redacts; reading the call site no longer
tells you the full table.

### Migration recipe

If your adapter only declares custom tools (no overlap with
chio-default tool names), no code change is needed -- but add the
chio-default merge anyway as a defensive measure in case a future
chio-default tool name overlaps with yours:

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

If you cannot tell from your call site whether the implicit
extend was load-bearing, audit by grepping for
`positional_table=` in your adapter and inspecting each call's
table contents:

```bash
grep -rn 'positional_table=' src/
```

For each hit, if the table contains a chio-default tool name
(`chio_file_write`, `chio_file_edit`), the override is
intentional. If it contains only adapter-specific tool names,
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

2. **Keyword-only alias** (new in 0.2.0): assert that
   `f(*, content)` calls redact `content` even when it arrives
   as a kwarg.

3. **Merge-conflict TypeError fallback** (new in 0.2.0): assert
   that a duplicate-name positional + kwarg call still produces
   a redacted output dict containing the protected field.

4. **Pure `VAR_POSITIONAL` with named slot** (new in 0.2.0):
   assert that `f(*content)` against a `positional_table` that
   declares `("content",)` redacts each variadic value.

5. **Custom `positional_table` replace semantic** (new in
   0.2.0): assert that a custom table NOT containing
   `chio_file_write` does not redact `chio_file_write` calls
   under that table (proves replace, not extend, is in
   effect).

6. **Byte-count invariant**: for every redacted field, assert
   `byte_count == len(value.encode("utf-8"))` (or
   `len(value)` for `bytes` / `bytearray`).

If your adapter has a parity shim wrapping `bind_and_redact`
back into a legacy envelope shape, also assert that the shim's
output is byte-identical to a pre-migration golden snapshot for
at least one call per signature shape your adapter wraps.
