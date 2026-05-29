"""Behavioural tests for :func:`chio_adapter_base.redact.bind_and_redact`.

6-axis coverage matrix
======================

Tests reference cells from the orthogonal axis combinatoric below.

1. Signature shape:
   - SS1 fixed-positional
   - SS2 fixed+kwonly
   - SS3 fixed+VAR_POSITIONAL
   - SS4 fixed+VAR_KEYWORD
   - SS5 pure VAR_POSITIONAL
   - SS6 pure VAR_KEYWORD
   - SS7 pure VAR_POSITIONAL+VAR_KEYWORD
   - SS8 fn=None
   - SS9 non-introspectable callable
2. Args presence:
   - AP1 empty
   - AP2 single positional
   - AP3 multiple positional
   - AP4 more positional than fixed slots
3. Kwargs presence:
   - KP1 empty
   - KP2 single matching
   - KP3 single non-matching
   - KP4 conflict with positional slot
4. Default-table presence:
   - DT1 tool in DEFAULT_TOOL_POSITIONAL_NAMES
   - DT2 tool not in default
5. Policy:
   - PO1 chio_default()
   - PO2 custom matching
   - PO3 custom non-matching
6. positional_table override:
   - OV1 None
   - OV2 caller-supplied (REPLACES the default; locked v0.3 semantic)
   - OV3 caller-supplied (custom-tool only)

Cell-to-test map (representative, non-exhaustive):

| Cell                       | Test                                                  |
| -------------------------- | ----------------------------------------------------- |
| SS1 / AP3 / KP1 / DT1      | test_bind_and_redact_fixed_signature_positional_*     |
| SS1 / AP1 / KP2 / DT1      | test_bind_and_redact_fixed_signature_kwarg_*          |
| SS1 / AP2 / KP4 / DT1      | test_bind_and_redact_merge_conflict_*                 |
| SS2 / AP2 / KP2 / DT1      | test_keyword_only_alias_for_protected_field_*         |
| SS2 / AP2 / KP2 / DT1      | test_kwonly_alias_in_typeerror_fallback_*             |
| SS3 / AP4 / KP1 / DT1      | test_var_positional_extras_redacted_via_*             |
| SS3 / AP2 / KP2 / DT1      | test_var_positional_with_kwarg_consuming_*            |
| SS4 / AP2 / KP3 / DT1      | test_bind_and_redact_var_keyword_spillover_*          |
| SS5 / AP2 / KP1 / DT1      | test_pure_var_positional_treated_as_*                 |
| SS5 / AP2 / KP1 / DT2      | test_pure_var_positional_named_for_protected_*        |
| SS7 / AP2 / KP4 / DT1      | test_pure_forwarder_skips_table_slot_*                |
| SS8 / AP3 / KP1 / DT1      | test_bind_and_redact_fn_none_*                        |
| SS9 / AP3 / KP1 / DT1      | test_bind_and_redact_c_extension_callable_*           |
| SS1 / AP3 / KP1 / DT1      | test_index_collision_does_not_corrupt_redaction       |
| SS1 / AP4 / KP4 / OV2/DT2  | test_custom_positional_table_replaces_default_*       |
| SS1 / AP3 / KP4 / DT1      | test_typeerror_fallback_preserves_alias_map_*         |

Cells documented as out-of-scope (covered by fail-closed semantics):
- ``replaces default + non-introspectable callable``: callers passing
  a custom positional_table for ``fn=None``/C-extension paths get the
  documented "replaces the chio default" semantic; no extra coverage.
- ``custom non-matching policy + tool in default table``: a policy
  that does not declare any field for the tool yields a no-op redact;
  exercised indirectly via ``test_unrelated_tool_passes_*``-shape
  prefect tests.
"""

from __future__ import annotations

import inspect

import pytest

from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
)


def test_bind_and_redact_fn_none_uses_positional_table() -> None:
    """``fn=None`` should still redact via the chio default table."""
    args, kwargs = bind_and_redact(
        None,
        ("src/main.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 17}
    assert kwargs == {}


def test_bind_and_redact_c_extension_callable_fallback() -> None:
    """Non-introspectable callables (e.g. builtins) fall back to the table."""
    try:
        inspect.signature(dict.update)
        pytest.skip("builtin is now introspectable on this Python")
    except (TypeError, ValueError):
        pass

    args, kwargs = bind_and_redact(
        dict.update,
        ("path/to/file.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "path/to/file.py"
    assert args[1] == {"omitted": True, "byte_count": 17}


def test_bind_and_redact_pure_forwarder_uses_positional_table() -> None:
    """``def f(*args, **kwargs)`` carries no name info; use the table."""

    def forwarder(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        forwarder,
        ("src/main.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 17}


def test_bind_and_redact_fallback_unknown_tool_forwards_args_raw() -> None:
    """No table entry, no signature: kwargs redacted, args raw."""
    args, kwargs = bind_and_redact(
        None,
        ("positional-secret",),
        {"content": "kwarg-secret"},
        tool_name="chio_file_write",
    )
    assert args == ["positional-secret"]
    assert kwargs["content"] == {"omitted": True, "byte_count": 12}


def test_bind_and_redact_fixed_signature_positional_preserved() -> None:
    """Positional values stay positional after redaction."""

    def chio_file_write(path: str, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("src/main.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
    )
    assert args == [
        "src/main.py",
        {"omitted": True, "byte_count": 17},
    ]
    assert kwargs == {}


def test_bind_and_redact_fixed_signature_kwarg_preserved() -> None:
    """Kwarg values stay in kwargs after redaction."""

    def chio_file_write(path: str, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        chio_file_write,
        (),
        {"path": "src/main.py", "content": "SECRET=topsecret\n"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs == {
        "path": "src/main.py",
        "content": {"omitted": True, "byte_count": 17},
    }


def test_bind_and_redact_fixed_signature_mixed_args_kwargs() -> None:
    """Path positional, content kwarg -- both placed correctly."""

    def chio_file_write(path: str, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("src/main.py",),
        {"content": "SECRET\n"},
        tool_name="chio_file_write",
    )
    assert args == ["src/main.py"]
    assert kwargs == {"content": {"omitted": True, "byte_count": 7}}


def test_bind_and_redact_var_positional_extras_unredacted() -> None:
    """Extras into ``*args`` past every table slot stay positional and raw."""

    def chio_file_write(path: str, content: str, *extras: object) -> None:
        del path, content, extras

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("src/main.py", "SECRET\n", "extra1", "extra2"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 7}
    # Both table slots ("path", "content") are filled by fixed bindings,
    # so the trailing VAR_POSITIONAL extras have no free slot to bind to
    # and surface raw.
    assert args[2:] == ["extra1", "extra2"]
    assert kwargs == {}


def test_var_positional_extras_redacted_via_positional_table() -> None:
    """``def fn(path, *rest)`` -- rest[0] binds to the next free table slot.

    For ``chio_file_write`` the table is ``("path", "content")``; the
    fixed positional fills slot 0 (``path``), so ``rest[0]`` matches the
    next free slot ``content`` and is redacted. Mirrors the prefect
    local-helper fix (cba84f66c) for the chio-adapter-base helper that
    chio-ray and other sibling adapters consume.
    """

    def chio_file_write(path: str, *rest: object) -> None:
        del path, rest

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("/tmp/x", "PROD_SECRET"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {}


def test_var_positional_with_kwarg_consuming_first_table_slot() -> None:
    """``def fn(*content, path)`` -- content[0] binds via the table.

    Calling ``fn("PROD_SECRET", path="/tmp/x")`` binds the ``path``
    kwarg to table slot 0, so the lone VAR_POSITIONAL value finds the
    next free table slot ``content`` and is redacted. This is the
    direct counterpart of the prefect leak path closed in cba84f66c.
    """

    def write_file(*content: object, path: str) -> None:
        del content, path

    args, kwargs = bind_and_redact(
        write_file,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {"path": "/tmp/x"}


def test_bind_and_redact_var_keyword_spillover_redacted() -> None:
    """Protected fields that arrive via ``**kwargs`` spillover are redacted."""

    def some_wrapper(path: str, **rest: object) -> None:
        del path, rest

    args, kwargs = bind_and_redact(
        some_wrapper,
        ("src/main.py",),
        {"content": "SECRET\n", "other": "ok"},
        tool_name="chio_file_write",
    )
    assert args == ["src/main.py"]
    assert kwargs["content"] == {"omitted": True, "byte_count": 7}
    assert kwargs["other"] == "ok"


def test_bind_and_redact_drop_self_with_non_self_receiver() -> None:
    """``drop_self=True`` skips the first positional regardless of its name."""

    def method(this: object, path: str, content: str) -> None:
        del this, path, content

    receiver = object()
    args, kwargs = bind_and_redact(
        method,
        (receiver, "src/main.py", "SECRET\n"),
        {},
        tool_name="chio_file_write",
        drop_self=True,
    )
    # Receiver is restored at position 0; we only adjust the signature
    # for binding, not the caller's positional list.
    assert args[0] is receiver
    assert args[1] == "src/main.py"
    assert args[2] == {"omitted": True, "byte_count": 7}


def test_bind_and_redact_merge_conflict_redacts_both_positions() -> None:
    """Same name in positional and kwargs: redact both; let TypeError surface."""

    def chio_file_write(path: str, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("src/main.py", "POSITIONAL-SECRET"),
        {"content": "KWARG-SECRET"},
        tool_name="chio_file_write",
    )
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 17}
    assert kwargs == {"content": {"omitted": True, "byte_count": 12}}


def test_bind_and_redact_custom_positional_table_overrides_default() -> None:
    """Custom tables let adapters redact their own tools without a signature."""

    custom_table = {"my_tool": ("path", "body")}
    custom_policy = RedactionPolicy(body_fields={"my_tool": ("body",)})

    args, kwargs = bind_and_redact(
        None,
        ("docs/x.md", "BODY-SECRET"),
        {},
        tool_name="my_tool",
        policy=custom_policy,
        positional_table=custom_table,
    )
    assert args[0] == "docs/x.md"
    assert args[1] == {"omitted": True, "byte_count": 11}
    assert kwargs == {}


def test_drop_self_strips_receiver_when_signature_unavailable() -> None:
    """``drop_self=True`` must strip the receiver even with no signature."""
    receiver = object()

    args, kwargs = bind_and_redact(
        None,
        (receiver, "src/main.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
        drop_self=True,
    )
    assert args[0] is receiver
    assert args[1] == "src/main.py"
    assert args[2] == {"omitted": True, "byte_count": 17}
    assert kwargs == {}

    # C-extension callable path (non-introspectable); reuse dict.update.
    try:
        inspect.signature(dict.update)
        c_ext_introspectable = True
    except (TypeError, ValueError):
        c_ext_introspectable = False
    if not c_ext_introspectable:
        args, kwargs = bind_and_redact(
            dict.update,
            (receiver, "src/main.py", "SECRET=topsecret\n"),
            {},
            tool_name="chio_file_write",
            drop_self=True,
        )
        assert args[0] is receiver
        assert args[1] == "src/main.py"
        assert args[2] == {"omitted": True, "byte_count": 17}


def test_pure_var_positional_treated_as_forwarder() -> None:
    """``def fn(*args)`` (no fixed params) must use the table fallback."""

    def writer(*args: object) -> None:
        del args

    args, kwargs = bind_and_redact(
        writer,
        ("src/main.py", "SECRET=topsecret\n"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 17}
    assert kwargs == {}

    def kwargs_only(**kwargs: object) -> None:
        del kwargs

    args, kwargs = bind_and_redact(
        kwargs_only,
        (),
        {"path": "src/main.py", "content": "SECRET\n"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs["path"] == "src/main.py"
    assert kwargs["content"] == {"omitted": True, "byte_count": 7}


def test_fixed_signature_redacts_both_positional_and_kwarg_for_protected_slot() -> None:
    """Custom-tool merge conflict: redact both positional + kwarg without a custom table.

    A fixed-signature custom tool (``def my_tool(path, body)``) called
    with a duplicate protected name (``my_tool("p", "SECRET", body="KW")``)
    makes ``bind_partial`` raise. The chio-default positional table has
    no entry for ``my_tool``, so without a signature-derived fallback the
    positional ``body`` value is returned raw. The fallback positional
    names are derived from the signature itself when the caller has not
    supplied a ``positional_table=`` for the tool.
    """

    def my_tool(path: str, body: str) -> None:
        del path, body

    custom_policy = RedactionPolicy(body_fields={"my_tool": ("body",)})

    args, kwargs = bind_and_redact(
        my_tool,
        ("p", "POS-SECRET"),
        {"body": "KW-SECRET"},
        tool_name="my_tool",
        policy=custom_policy,
    )
    assert args[0] == "p"
    assert args[1] == {"omitted": True, "byte_count": 10}
    assert kwargs == {"body": {"omitted": True, "byte_count": 9}}


def test_var_positional_named_after_protected_chio_default() -> None:
    """``def fn(*content, path)`` for chio_file_write: each ``*content`` value redacts.

    The wrapper's varargs parameter is itself the protected field name
    (``content``). If the rebuild loop ignored the declared ``*content``
    name and bound extras only via the positional table, then because
    ``path`` already filled the table's ``path`` slot via kwargs, the
    first content chunk would be treated as ``path`` and returned raw.
    """

    def write_file(*content: object, path: str) -> None:
        del content, path

    args, kwargs = bind_and_redact(
        write_file,
        ("PROD_SECRET_A", "PROD_SECRET_B"),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_A"),
    }
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_B"),
    }
    assert kwargs == {"path": "/tmp/x"}


def test_var_positional_named_after_protected_custom_tool() -> None:
    """Same wrapper shape with a custom tool/policy: every chunk redacts."""

    def upload(*payload: object, dest: str) -> None:
        del payload, dest

    custom_policy = RedactionPolicy(body_fields={"my_upload": ("payload",)})

    args, kwargs = bind_and_redact(
        upload,
        ("CHUNK_A", "CHUNK_B"),
        {"dest": "remote://x"},
        tool_name="my_upload",
        policy=custom_policy,
    )
    assert args[0] == {"omitted": True, "byte_count": 7}
    assert args[1] == {"omitted": True, "byte_count": 7}
    assert kwargs == {"dest": "remote://x"}


def test_positional_only_with_same_named_kwarg_preserves_spillover() -> None:
    """``def write(path, /, **kw)`` called as ``write("/etc", path="/tmp/x")``.

    Python permits both a positional-only ``path`` and a
    same-named entry in ``**kw``. ``bind_partial`` keeps the
    kwarg in the VAR_KEYWORD spillover; the rebuild loop must not
    match ``redacted_fixed`` first and replace the spillover value
    with the positional value. Each redacts independently; the
    original wire shape preserves both.
    """

    def write(path: str, /, **kw: object) -> None:
        del path, kw

    args, kwargs = bind_and_redact(
        write,
        ("/etc",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    # Positional ``path`` is not a protected field so it is not
    # redacted; the value must remain ``/etc`` (the positional).
    assert args == ["/etc"]
    # The spillover kwarg is also not a protected field, but it
    # must remain ``/tmp/x`` (the kwarg) and NOT be silently
    # replaced by the positional value.
    assert kwargs == {"path": "/tmp/x"}


def test_positional_only_with_same_named_protected_kwarg_redacts_both() -> None:
    """``def write(content, /, **kw)`` with both protected: each redacts independently."""

    def write(content: str, /, **kw: object) -> None:
        del content, kw

    args, kwargs = bind_and_redact(
        write,
        ("POS-SECRET",),
        {"content": "KW-SECRET"},
        tool_name="chio_file_write",
    )
    assert args == [{"omitted": True, "byte_count": 10}]
    assert kwargs == {"content": {"omitted": True, "byte_count": 9}}


def test_known_tool_with_renamed_param_redacts_correctly() -> None:
    """Wrapper renames the canonical body field; rebuild still redacts.

    When a wrapper for a
    chio-default tool uses a non-canonical parameter name (here
    ``def write_file(path, body)`` against ``chio_file_write`` whose
    canonical slots are ``("path", "content")``), the rebuild must
    route the value through the table-derived canonical name so the
    policy lookup matches. If the wrapper's ``body`` name were used
    directly, the ``content``-keyed policy would miss it and leak the
    raw secret in ``parameters["args"][1]``.
    """

    def write_file(path: str, body: str) -> None:
        del path, body

    # Pure positional call.
    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "PROD_SECRET"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {}

    # Mixed positional + kwarg under the wrapper's renamed name.
    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x",),
        {"body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs == {
        "body": {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    }

    # Pure kwarg call under the wrapper's renamed name.
    args, kwargs = bind_and_redact(
        write_file,
        (),
        {"path": "/tmp/x", "body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs["path"] == "/tmp/x"
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_pure_forwarder_skips_table_slot_filled_by_kwarg() -> None:
    """Pure forwarder fallback maps positional[0] to next free slot.

    A pure-forwarding wrapper
    (``def proxy(*args, **kwargs)``) registered as ``chio_file_write``
    called as ``proxy("PROD_SECRET", path="/tmp/x")``. The kwarg already
    fills slot 0 (``path``), so the lone positional value is logically
    the ``content`` slot. A fallback that always mapped
    positional[0] -> table slot 0 would return the raw secret under
    ``args[0]``.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args == [{"omitted": True, "byte_count": len(b"PROD_SECRET")}]
    assert kwargs == {"path": "/tmp/x"}

    # Same shape with ``fn=None`` (the other table-fallback entry).
    args, kwargs = bind_and_redact(
        None,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args == [{"omitted": True, "byte_count": len(b"PROD_SECRET")}]
    assert kwargs == {"path": "/tmp/x"}


def test_default_tool_positional_names_covers_chio_default_tools() -> None:
    """The default table must mirror the chio_default redaction policy."""

    policy = RedactionPolicy.chio_default()
    for tool_name, fields in policy.body_fields.items():
        assert tool_name in DEFAULT_TOOL_POSITIONAL_NAMES, (
            f"{tool_name} is in chio_default redaction policy but not "
            "in DEFAULT_TOOL_POSITIONAL_NAMES; the fallback path cannot "
            "redact positional args for this tool."
        )
        positional_names = DEFAULT_TOOL_POSITIONAL_NAMES[tool_name]
        for field in fields:
            assert field in positional_names, (
                f"{tool_name}.{field} is redacted by policy but not "
                "reachable via the positional-name fallback table."
            )


def test_signature_param_order_overrides_default_table_for_renamed_protected_field() -> None:
    """E1 regression: when wrapper renames protected fields (e.g. content/path
    swapped), the signature-derived names take precedence over the default
    table so the protected slot is redacted at the right index.
    """

    def write(content: str, path: str) -> None:
        del content, path

    args, kwargs = bind_and_redact(
        write,
        ("PROD_SECRET", "/tmp/x"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": 11}
    assert args[1] == "/tmp/x"
    assert kwargs == {}


def test_keyword_only_alias_for_protected_field_redacts_via_canonical() -> None:
    """A TaskFlow wrapper with a keyword-only
    alias for the protected body must still redact via the canonical
    slot name. ``def write_file(path, *, body)`` registered as
    ``chio_file_write`` (table ``("path", "content")``) must not be
    omitted from the alias map merely because the kwonly param is not in
    the fixed-positional collection.
    """

    def write_file(path: str, *, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x",),
        {"body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs == {
        "body": {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    }

    # Wrapper that uses the canonical name as the kwonly param: redact
    # by name as-is, no aliasing needed.
    def write_canonical(path: str, *, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        write_canonical,
        ("/tmp/x",),
        {"content": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs == {
        "content": {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    }


def test_pure_forwarder_redacts_both_positional_and_kwarg_for_same_slot() -> None:
    """A pure-forwarding wrapper that receives
    the protected slot both positionally and as a kwarg must redact both
    independently. ``proxy("/tmp/x", "POS_SECRET", content="KW_SECRET")``
    for ``chio_file_write`` must not drop the positional ``POS_SECRET``
    to raw when the kwarg has already removed the ``content`` slot from
    the free-slot sequence.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        ("/tmp/x", "POS_SECRET"),
        {"content": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == [
        "/tmp/x",
        {"omitted": True, "byte_count": len(b"POS_SECRET")},
    ]
    assert kwargs == {
        "content": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }

    # Same shape via fn=None (the other table-fallback entry).
    args, kwargs = bind_and_redact(
        None,
        ("/tmp/x", "POS_SECRET"),
        {"content": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == [
        "/tmp/x",
        {"omitted": True, "byte_count": len(b"POS_SECRET")},
    ]
    assert kwargs == {
        "content": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }


# ---------------------------------------------------------------------------


def test_index_collision_does_not_corrupt_redaction_when_renamed_protected_first() -> None:  # noqa: E501
    """Cell SS1 / AP3 / KP1 / DT1.

    Wrapper renames a protected slot AND swaps the canonical-name slot
    later: ``def write(body, path)`` for ``chio_file_write`` whose
    table is ``("path", "content")``. The earlier "alias by same-index
    table slot" rule would have aliased ``body`` (idx 0) to ``path``
    (the unprotected canonical at idx 0), preventing redaction. The
    fix routes wrapper-renamed names to the next UNCLAIMED PROTECTED
    canonical, not the same-index slot.
    """

    def write(body: str, path: str) -> None:
        del body, path

    args, kwargs = bind_and_redact(
        write,
        ("PROD_SECRET", "/tmp/x"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert args[1] == "/tmp/x"
    assert kwargs == {}


def test_index_collision_via_kwarg_call_routes_to_protected_canonical() -> None:
    """Cell SS1 / AP1 / KP2 / DT1.

    Same wrapper shape as above (``def write(body, path)``) but called
    purely with kwargs. The wrapper-renamed ``body`` kwarg must redact
    via the protected canonical ``content``.
    """

    def write(body: str, path: str) -> None:
        del body, path

    args, kwargs = bind_and_redact(
        write,
        (),
        {"body": "PROD_SECRET", "path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs["path"] == "/tmp/x"
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_typeerror_fallback_arity_mismatch_keeps_alias_map() -> None:
    """Cell SS1 / AP4 / KP1 / DT1.

    A wrapper with a renamed protected param hit by an arity mismatch
    (more positional args than the signature accepts) blows
    ``bind_partial`` up. The fallback must preserve the wrapper's
    canonical alias map so the positional secret is still redacted via
    the table the helper derives from the signature.
    """

    def write_file(path: str, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        # Three positional args, only two slots: TypeError on bind_partial.
        ("/tmp/x", "PROD_SECRET", "trailing"),
        {},
        tool_name="chio_file_write",
    )
    # The signature-derived fallback table is ("path", "body"); the
    # alias map routes ``body`` -> ``content`` so the second positional
    # is redacted under the protected canonical, then re-emitted into
    # the wrapper-named slot at args[1].
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert args[2] == {"omitted": True, "byte_count": len(b"trailing")}


def test_alias_map_redacts_kwarg_under_canonical_no_fallback() -> None:
    """Cell SS1 / AP3 / KP4 / DT1.

    Same renamed-protected wrapper as above. The original test name
    referenced a TypeError fallback path, but ``bind_partial`` actually
    succeeds here (path positional + body kwarg, no duplicate keyword
    or arity mismatch); the non-fallback path is what runs. Both
    buckets must still redact independently under the wrapper's alias
    map so the kwarg supplied under the wrapper's renamed name
    (``body=``) redacts as the canonical ``content``.
    """

    def write_file(path: str, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "POS_SECRET"),
        {"body": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    # bind_partial succeeds here (path positional, body kwarg, no
    # duplicate). The non-fallback path applies; both buckets must
    # redact independently under the wrapper's alias map.
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"POS_SECRET")}
    assert kwargs == {
        "body": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }


def test_kwonly_alias_in_typeerror_fallback() -> None:
    """Cell SS2 / AP2 / KP4 / DT1.

    A wrapper with both a renamed positional protected slot AND a
    kwonly alias gets hit by a duplicate-keyword TypeError. The alias
    map must include the kwonly name so its redaction still applies.
    """

    def write_file(path: str, *, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        # Path positional + same-named kwarg triggers TypeError.
        ("/tmp/x",),
        {"path": "/etc/dup", "body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    # Path positional is preserved; both `path` kwarg and `body` kwarg
    # round-trip with redaction via the canonical alias.
    assert args[0] == "/tmp/x"
    assert kwargs["path"] == "/etc/dup"
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_pure_var_positional_named_for_protected_field_uses_signature_path() -> None:  # noqa: E501
    """Cell SS5 / AP2 / KP1 / DT2.

    ``def upload(*payload)`` against a custom policy declaring
    ``payload`` as the protected field. The earlier
    ``_is_pure_forwarder`` returned True for this shape (no fixed
    params), shoving the call into the table fallback that has no
    entry for ``my_upload``. The fix detects the variadic-name match
    and runs the signature path so each ``*payload`` value redacts
    under the canonical name.
    """

    def upload(*payload: object) -> None:
        del payload

    custom_policy = RedactionPolicy(body_fields={"my_upload": ("payload",)})

    args, kwargs = bind_and_redact(
        upload,
        ("CHUNK_A", "CHUNK_B"),
        {},
        tool_name="my_upload",
        policy=custom_policy,
    )
    assert args[0] == {"omitted": True, "byte_count": 7}
    assert args[1] == {"omitted": True, "byte_count": 7}
    assert kwargs == {}


def test_pure_var_positional_named_for_protected_field_with_var_keyword() -> None:  # noqa: E501
    """Cell SS7 / AP2 / KP1 / DT2.

    ``def upload(*payload, **opts)`` for the same custom-tool policy.
    Even with a sibling VAR_KEYWORD, the variadic-name match must
    still elect the signature path.
    """

    def upload(*payload: object, **opts: object) -> None:
        del payload, opts

    custom_policy = RedactionPolicy(body_fields={"my_upload": ("payload",)})

    args, kwargs = bind_and_redact(
        upload,
        ("CHUNK_A",),
        {"trace_id": "abc"},
        tool_name="my_upload",
        policy=custom_policy,
    )
    assert args[0] == {"omitted": True, "byte_count": 7}
    assert kwargs == {"trace_id": "abc"}


def test_pure_var_positional_named_for_protected_field_chio_default() -> None:
    """Cell SS5 / AP2 / KP1 / DT1.

    Prefect-side surface: ``def write_file(*content)`` against
    chio_file_write's default policy. The variadic-name ``content``
    matches a chio-default protected field; signature path takes over.
    """

    def write_file(*content: object) -> None:
        del content

    args, kwargs = bind_and_redact(
        write_file,
        ("PROD_SECRET",),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {}


def test_custom_positional_table_replaces_default_locked_v0_3_semantic() -> None:  # noqa: E501
    """Cell SS8 / AP3 / KP1 / OV2.

    The v0.3 contract LOCKS ``positional_table`` as REPLACES (current
    behavior) rather than EXTENDS. A caller-supplied table fully
    replaces the chio-default for the lookup; chio-default tools NOT
    listed in the override become unredactable via the fallback path.
    Documented as a breaking note in the 0.2.0 CHANGELOG so external
    consumers who relied on extends semantics see the change.
    """

    custom_table = {"my_tool": ("path", "body")}
    custom_policy = RedactionPolicy(
        body_fields={
            "my_tool": ("body",),
            "chio_file_write": ("content",),
        }
    )

    # The override REPLACES the default: chio_file_write is NOT in the
    # override, so its positional fallback finds no slots and the
    # positional secret stays raw (documented limitation; callers
    # supplying a custom table for one tool keep using the chio-default
    # for others by merging themselves).
    args, kwargs = bind_and_redact(
        None,
        ("/tmp/x", "PROD_SECRET"),
        {},
        tool_name="chio_file_write",
        policy=custom_policy,
        positional_table=custom_table,
    )
    # No table entry for chio_file_write under the override; positional
    # values forward raw (kwargs would still redact by name).
    assert args == ["/tmp/x", "PROD_SECRET"]

    # The override IS used for my_tool.
    args2, kwargs2 = bind_and_redact(
        None,
        ("/x", "BODY-SECRET"),
        {},
        tool_name="my_tool",
        policy=custom_policy,
        positional_table=custom_table,
    )
    assert args2[0] == "/x"
    assert args2[1] == {"omitted": True, "byte_count": 11}
    assert kwargs2 == {}


def test_kwarg_filling_table_slot_does_not_leak_positional_when_renamed_wrapper() -> None:  # noqa: E501
    """Cell SS1 / AP2 / KP4 / DT1.

    Wrapper renames protected slot, kwarg supplies the wrapper's
    renamed name AND a positional secret arrives. Both buckets must
    redact independently; neither should be silently dropped.
    """

    def write_file(path: str, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "POS_SECRET"),
        {"body": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"POS_SECRET")}
    assert kwargs == {
        "body": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }


def test_typeerror_fallback_two_kwargs_same_canonical_both_redact() -> None:
    """Cell SS1 / AP1 / KP4 / DT1.

    Two distinct kwarg names resolve to the SAME canonical: a wrapper
    aliases ``body`` -> canonical ``content`` AND the caller passes both
    ``body=`` AND a literal ``content=`` in the same call. Both buckets
    must redact independently and round-trip under their original
    wrapper-name keys; neither value may be silently dropped.

    Before the C1 fix, the TypeError-fallback alias-map path collapsed
    both values into a single ``canonical_view[canonical]`` entry, so
    the second kwarg overwrote the first and only one bucket survived
    in the rebuilt ``redacted_kwargs``. The fix mirrors the
    merge-conflict semantics from the variadic / overflow paths:
    redact each kwarg independently, keyed by its ORIGINAL wrapper
    name.
    """

    def write(body: str, path: str) -> None:
        del body, path

    # ``content=`` is not a parameter of ``write``; bind_partial raises
    # TypeError, dropping the helper into the alias-map fallback path
    # where C1 must not drop either of the two kwargs.
    args, kwargs = bind_and_redact(
        write,
        (),
        {"body": "BODY_SECRET", "content": "CONTENT_SECRET"},
        tool_name="chio_file_write",
    )
    # Both kwargs survive with their own redaction record. Neither key
    # collapses onto the other; neither value is silently lost.
    assert args == []
    assert set(kwargs.keys()) == {"body", "content"}
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"BODY_SECRET"),
    }
    assert kwargs["content"] == {
        "omitted": True,
        "byte_count": len(b"CONTENT_SECRET"),
    }


def test_pure_forwarder_kwarg_aliasing_does_not_break_existing_path() -> None:
    """Cell SS7 / AP2 / KP3 / DT1.

    A pure-forwarder wrapper called with a non-table kwarg name must
    not invent an alias. ``proxy("PROD_SECRET", marker="ok")`` for
    chio_file_write redacts the positional via table slot 0 and leaves
    the kwarg raw.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        ("PROD_SECRET",),
        {"marker": "ok"},
        tool_name="chio_file_write",
    )
    # No kwarg fills any table slot; positional[0] -> table[0] = path
    # (which is not protected), so the secret stays raw. This is the
    # documented fallback-path limitation.
    assert args == ["PROD_SECRET"]
    assert kwargs == {"marker": "ok"}


def test_pure_forwarder_with_kwarg_canonical_redirects_positional_to_protected() -> None:  # noqa: E501
    """Cell SS7 / AP2 / KP2 / DT1.

    Pure-forwarder with a kwarg consuming the unprotected canonical
    slot (``path``); the positional value rolls onto the next free
    slot (``content``) and redacts.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {"path": "/tmp/x"}


def test_known_tool_with_canonical_kwarg_filling_unprotected_slot() -> None:
    """Cell SS1 / AP2 / KP2 / DT1.

    ``def write(content, path)`` (canonical names, swapped order)
    called as ``write("PROD_SECRET", path="/tmp/x")``. The wrapper's
    positional ``content`` is the protected field; redacts at args[0].
    """

    def write(content: str, path: str) -> None:
        del content, path

    args, kwargs = bind_and_redact(
        write,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {"path": "/tmp/x"}


def test_var_positional_after_protected_kwarg_redacts_extras() -> None:
    """Cell SS3 / AP4 / KP2 / DT1.

    ``def fn(path, *rest, **kw)`` with the kwarg consuming the
    canonical protected slot. The VAR_POSITIONAL extras must STILL
    redact under the canonical name (the kwarg-filled slot does not
    pre-empt the VAR_POSITIONAL aliasing for the same canonical).
    """

    def fn(path: str, *rest: object, **kw: object) -> None:
        del path, rest, kw

    # The kwarg supplies the canonical slot AND a *rest extra carries
    # the positional secret. Both buckets must redact independently.
    args, kwargs = bind_and_redact(
        fn,
        ("/tmp/x", "PROD_SECRET"),
        {"content": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    # path is at args[0]. content kwarg redacts. rest[0] is the
    # positional secret.
    assert args[0] == "/tmp/x"
    # rest[0] redacts via the named-variadic / table path: the table
    # slot ``content`` is filled by kwarg, but the merge-conflict
    # semantics still redact the positional value independently.
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {
        "content": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }


def test_var_positional_after_protected_kwarg_redacts_extras_alt_shape() -> None:  # noqa: E501
    """Cell SS3 / AP4 / KP1 / DT1.

    ``def fn(path, *rest, **kw)`` purely positional: rest[0] is the
    secret. The variadic redacts via table slot 1 (``content``).
    """

    def fn(path: str, *rest: object, **kw: object) -> None:
        del path, rest, kw

    args, kwargs = bind_and_redact(
        fn,
        ("/tmp/x", "PROD_SECRET"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert kwargs == {}


def test_custom_policy_without_positional_table_redacts_kwargs() -> None:
    """Cell SS6 / AP1 / KP2 / DT2.

    A custom policy for a tool not in any positional_table at all -
    kwargs-only redaction is the fail-closed contract. Positional args
    forward raw (documented limitation).
    """

    def fn(**kwargs: object) -> None:
        del kwargs

    custom_policy = RedactionPolicy(body_fields={"my_tool": ("body",)})

    args, kwargs = bind_and_redact(
        fn,
        (),
        {"body": "PROD_SECRET"},
        tool_name="my_tool",
        policy=custom_policy,
    )
    assert args == []
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_custom_policy_without_positional_table_pure_forwarder_kwargs() -> None:
    """Cell SS7 / AP1 / KP2 / DT2.

    Pure-forwarder, custom-policy tool, kwargs-only call: kwargs
    redact under the policy.
    """

    def fn(*args: object, **kwargs: object) -> None:
        del args, kwargs

    custom_policy = RedactionPolicy(body_fields={"my_tool": ("body",)})

    args, kwargs = bind_and_redact(
        fn,
        (),
        {"body": "PROD_SECRET", "label": "x"},
        tool_name="my_tool",
        policy=custom_policy,
    )
    assert args == []
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }
    assert kwargs["label"] == "x"


def test_custom_policy_without_table_positional_passes_raw_documented_limitation() -> None:  # noqa: E501
    """Cell SS7 / AP2 / KP1 / DT2.

    Pure-forwarder, custom-policy tool, positional-only call: no
    positional_table entry means no name to bind against; positional
    forwards raw. Documented as a fallback-path limitation;
    fail-closed semantic.
    """

    def fn(*args: object, **kwargs: object) -> None:
        del args, kwargs

    custom_policy = RedactionPolicy(body_fields={"my_tool": ("body",)})

    args, kwargs = bind_and_redact(
        fn,
        ("PROD_SECRET",),
        {},
        tool_name="my_tool",
        policy=custom_policy,
    )
    assert args == ["PROD_SECRET"]
    assert kwargs == {}


def test_var_positional_named_after_protected_multi_chunk_emits_each() -> None:
    """Cell SS3 / AP4 / KP2 / DT1.

    ``def write_file(*content, path)`` with multiple chunks. Every
    chunk must redact under the variadic name; none silently dropped.
    """

    def write_file(*content: object, path: str) -> None:
        del content, path

    args, kwargs = bind_and_redact(
        write_file,
        ("CHUNK_1", "CHUNK_2", "CHUNK_3"),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": len(b"CHUNK_1")}
    assert args[1] == {"omitted": True, "byte_count": len(b"CHUNK_2")}
    assert args[2] == {"omitted": True, "byte_count": len(b"CHUNK_3")}
    assert kwargs == {"path": "/tmp/x"}


def test_pure_forwarder_kwarg_alias_not_invented_when_no_canonical_match() -> None:  # noqa: E501
    """Cell SS7 / AP1 / KP3 / DT1.

    Pure-forwarder, single non-matching kwarg, chio-default policy:
    no alias inference; kwarg passes through unredacted.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        (),
        {"trace_id": "abc"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs == {"trace_id": "abc"}


def test_pure_forwarder_positional_only_kwarg_redacts_under_canonical() -> None:
    """Cell SS7 / AP2 / KP2 / DT1.

    Same pure-forwarder shape but with the kwarg supplying the
    canonical protected name directly. Both buckets redact.
    """

    def proxy(*args: object, **kwargs: object) -> None:
        del args, kwargs

    args, kwargs = bind_and_redact(
        proxy,
        ("/tmp/x",),
        {"content": "KW_SECRET"},
        tool_name="chio_file_write",
    )
    # Positional[0] -> table[0] = "path" (kwarg "content" filled
    # table[1]); ``path`` is not protected, so positional stays raw.
    # The kwarg ``content`` redacts under canonical name.
    assert args == ["/tmp/x"]
    assert kwargs == {
        "content": {"omitted": True, "byte_count": len(b"KW_SECRET")}
    }


def test_temporal_extras_past_table_pass_through_raw_documented() -> None:
    """Cell SS3 / AP4 / KP1 / DT1.

    chio-temporal motivation: ``chio_file_write(path, content,
    overwrite)`` style call where a third positional ``overwrite``
    extends past the chio-default table cardinality. The known prefix
    (path, content) still redacts; the extra surfaces raw.
    """

    def write_file(path: str, content: str, overwrite: bool) -> None:
        del path, content, overwrite

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "PROD_SECRET", True),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    # The third positional has no slot in the chio-default table; it
    # surfaces raw because it is not a protected field by name either.
    assert args[2] is True
    assert kwargs == {}


def test_index_renamed_kwonly_with_typeerror_routes_via_alias() -> None:
    """Cell SS2 / AP3 / KP4 / DT1.

    Wrapper with renamed positional protected slot AND a kwonly alias,
    triggered into the TypeError fallback by an arity overflow.

    The overflow positional ``EXTRA`` redacts under the kwonly-aliased
    protected canonical (``content``) - the wrapped fn would reject this
    call anyway, but a leaky receipt is the worse failure mode.
    """

    def write_file(path: str, *, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        # Two positionals + the kwonly alias as kwarg: TypeError on
        # bind_partial because path takes positional 0 and there's no
        # second fixed positional slot.
        ("/tmp/x", "EXTRA"),
        {"body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    # Second positional borrows the kwonly alias's protected slot so the
    # overflow value is redacted instead of forwarded raw.
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"EXTRA"),
    }
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_typeerror_fallback_unknown_tool_only_redacts_kwargs() -> None:
    """Cell SS1 / AP4 / KP1 / DT2.

    Test integrity: the original
    ``test_bind_and_redact_fallback_unknown_tool_forwards_args_raw``
    used a known tool name; the v0.3 split confirms unknown-tool
    behaviour explicitly.
    """

    def fn(path: str, body: str) -> None:
        del path, body

    custom_policy = RedactionPolicy(body_fields={"unknown_tool": ("body",)})
    args, kwargs = bind_and_redact(
        fn,
        ("/tmp/x", "PROD_SECRET", "extra"),
        {"body": "KW_SECRET"},
        tool_name="not_in_any_table",
        policy=custom_policy,
    )
    # Tool not in policy.body_fields: kwargs pass through raw.
    assert kwargs == {"body": "KW_SECRET"}
    assert args[0] == "/tmp/x"
    # No protected field for this tool; positionals stay raw.
    assert args[1] == "PROD_SECRET"
    assert args[2] == "extra"


def test_signature_derived_table_overrides_default_in_typeerror_fallback() -> None:  # noqa: E501
    """Cell SS1 / AP3 / KP4 / DT1.

    E1 regression: the dict-spread in the TypeError fallback must put
    signature-derived names AFTER the caller table so they take
    precedence for the current tool (otherwise the chio-default
    ``("path", "content")`` would overwrite a renamed-slot wrapper).
    """

    # Wrapper renames both protected slots but keeps the same wire
    # ordering: positional 0 -> path, positional 1 -> the renamed body.
    def my_writer(p: str, b: str) -> None:
        del p, b

    args, kwargs = bind_and_redact(
        my_writer,
        ("/tmp/x", "POS"),
        {"b": "KW"},
        tool_name="chio_file_write",
    )
    # bind_partial raises (b given twice). The fallback derives
    # ("p", "b") from the signature; the alias map routes b -> content.
    # Positional 1 redacts (POS) and the kwarg b redacts (KW) -- both
    # under the protected canonical content via the alias.
    assert args[0] == "/tmp/x"
    assert args[1] == {"omitted": True, "byte_count": len(b"POS")}
    assert kwargs == {"b": {"omitted": True, "byte_count": len(b"KW")}}


def test_var_keyword_only_preserves_documented_kwargs_only_redact() -> None:
    """Cell SS6 / AP1 / KP2 / DT1.

    Pure VAR_KEYWORD wrapper; the positional-only same-named kwarg
    edge case is already covered by
    ``test_positional_only_with_same_named_kwarg_preserves_spillover``;
    this asserts the simpler kwargs-only path for completeness.
    """

    def fn(**kwargs: object) -> None:
        del kwargs

    args, kwargs = bind_and_redact(
        fn,
        (),
        {"path": "/tmp/x", "content": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    assert args == []
    assert kwargs["path"] == "/tmp/x"
    assert kwargs["content"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_typeerror_fallback_kwonly_protected_redacts_overflow_positional() -> None:
    """Cell SS2 / AP4 / KP1 / DT1.

    A wrapper that keeps the protected body in a keyword-only slot,
    invoked positionally by mistake, must redact the overflow
    positional under the kwonly slot's protected canonical instead of
    forwarding the secret raw. The wrapped fn would later raise
    TypeError, but that does not run before the receipt is emitted.
    """

    def write(path: str, *, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        write,
        ("/tmp/x", "PROD_SECRET"),
        {},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }
    assert kwargs == {}


def test_typeerror_fallback_protected_var_positional_with_unknown_kwarg() -> None:
    """Cell SS3 / AP2 / KP3 / DT1.

    A wrapper whose VAR_POSITIONAL is itself the protected canonical
    (``def write_file(*content)``), invoked with an unsupported kwarg
    so bind_partial raises, must still redact the positional values
    under the variadic name. The TypeError fallback must not drop the
    variadic-name slot list; otherwise the chio-default
    ``("path", "content")`` table routes the secret to the unprotected
    ``path`` slot.
    """

    def write_file(*content: str) -> None:
        del content

    args, kwargs = bind_and_redact(
        write_file,
        ("PROD_SECRET",),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }
    assert kwargs["path"] == "/tmp/x"


def test_typeerror_fallback_protected_var_positional_multi_chunk() -> None:
    """Multi-chunk variant: several positional values past the
    unsupported-kwarg trigger each redact under the variadic protected
    canonical, not just the first.

    Several positional values past the unsupported-kwarg trigger should
    each redact under the variadic protected canonical, not just the
    first one.

    Uses chunks of DISTINCT byte lengths so a regression that
    overwrites earlier values cannot hide behind matching
    ``byte_count`` records.
    """

    def write_file(*content: str) -> None:
        del content

    args, kwargs = bind_and_redact(
        write_file,
        ("S", "SS", "SSSS", "SSSSSSSS"),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    for idx, expected_len in enumerate((1, 2, 4, 8)):
        assert args[idx] == {
            "omitted": True,
            "byte_count": expected_len,
        }
    assert kwargs["path"] == "/tmp/x"


def test_typeerror_fallback_protected_var_positional_distinct_byte_counts() -> None:
    """Regression:

    The TypeError fallback pads ``extended_positional_names`` with the
    variadic slot name (e.g. ``("content", "content", "content")`` for
    ``def write_file(*content)``). Earlier the fallback then used the
    bare slot name as a dict key in ``named_from_positional`` so each
    positional value silently overwrote the previous one and every
    rebuilt position resolved to the LAST value's redacted record. Use
    distinct byte lengths so a regression can no longer hide behind
    matching ``byte_count`` records.
    """

    def write_file(*content: str) -> None:
        del content

    args, kwargs = bind_and_redact(
        write_file,
        ("A", "BB", "CCC"),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": 1}
    assert args[1] == {"omitted": True, "byte_count": 2}
    assert args[2] == {"omitted": True, "byte_count": 3}
    assert kwargs["path"] == "/tmp/x"


def test_signature_path_kwonly_body_with_unrelated_var_positional() -> None:
    """Regression:

    ``def write_file(path, *rest, body)`` invoked with the protected
    body as a kwarg. The kwonly aliasing pass must not be skipped merely
    because the signature contains any VAR_POSITIONAL. The guard defers
    to the variadic only when the variadic ITSELF names a protected
    canonical (e.g. ``def writer(*content, path)``); when the
    VAR_POSITIONAL is unrelated (``*rest``), the kwonly may still alias
    the protected body. A broad guard would let ``body='PROD_SECRET'``
    forward raw. Distinct byte length so a regression cannot hide behind
    a coincidentally-matching ``byte_count``.
    """

    def write_file(path: str, *rest: object, body: str) -> None:
        del path, rest, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x",),
        {"body": "PROD_SECRET_LONG_DISTINCT"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_LONG_DISTINCT"),
    }


def test_signature_path_ambiguous_kwonly_aliases_redact_all() -> None:
    """Regression:

    ``def write_file(path, *, label, body)`` invoked with both kwonly
    kwargs supplied. Pass-B must not walk the kwonly params in
    declaration order and greedily assign the only unclaimed protected
    canonical (``content``) to the first-declared kwonly (``label``),
    leaving ``body`` unaliased so ``body='PROD_SECRET'`` forwards raw.
    EVERY unclaimed kwonly routes to a protected canonical (cycling)
    when there are more kwonlys than free canonicals, mirroring the
    merge-conflict semantics used by other paths. Both kwargs must
    redact; each stub must report ITS OWN byte_count (not a shared one)
    so a regression can't hide.
    """

    def write_file(path: str, *, label: str, body: str) -> None:
        del path, label, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x",),
        {"body": "PROD_SECRET_BODY_LONGER", "label": "safe"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_BODY_LONGER"),
    }
    assert kwargs["label"] == {
        "omitted": True,
        "byte_count": len(b"safe"),
    }


def test_typeerror_fallback_protected_var_positional_distinct_lengths_strict() -> None:  # noqa: E501
    """Regression:

    ``def write_file(*content)`` invoked with ``args=("A","BB","CCC")``
    plus an unsupported ``path`` kwarg. Asserts each position reports
    its OWN value's byte_count (not the last value's length for every
    position), using DISTINCT byte lengths so an overwrite regression
    fails loudly. Complements
    ``test_typeerror_fallback_protected_var_positional_multi_chunk``
    by varying the input arity and chunk-shape so the contract is
    pinned from multiple angles.
    """

    def write_file(*content: str) -> None:
        del content

    args, kwargs = bind_and_redact(
        write_file,
        ("X" * 5, "Y" * 17, "Z" * 64),
        {"path": "/tmp/x"},
        tool_name="chio_file_write",
    )
    assert args[0] == {"omitted": True, "byte_count": 5}
    assert args[1] == {"omitted": True, "byte_count": 17}
    assert args[2] == {"omitted": True, "byte_count": 64}
    assert kwargs["path"] == "/tmp/x"


def test_typeerror_fallback_extra_positional_with_kwonly_label_and_body() -> None:
    """Regression:

    ``def write_file(path, *, label, body)`` invoked with one extra
    positional plus both kwonly kwargs supplied (``write_file('/tmp',
    'EXTRA', label='safe', body='PROD_SECRET')``). ``bind_partial``
    raises TypeError, the fallback runs, and the receipt is still
    emitted. The previous TypeError-fallback build_alias_map run
    greedily aliased ``label`` -> ``content`` and left ``body`` as
    self-aliased so ``body='PROD_SECRET'`` forwarded raw. The fix
    applies ambiguous-fail-closed to the fallback's kwonly aliasing
    pass, mirroring the non-fallback Pass-B semantics. Distinct byte
    lengths (5 / 4 / 11) so a future regression cannot hide behind a
    coincidentally-matching ``byte_count``.
    """

    def write_file(path: str, *, label: str, body: str) -> None:
        del path, label, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp", "EXTRA"),
        {"label": "safe", "body": "PROD_SECRET"},
        tool_name="chio_file_write",
    )
    # Positional overflow ``EXTRA`` lands in the kwonly-derived slot
    # ``label`` (sig_positional_names + kwonly_protected_slots).
    assert args[0] == "/tmp"
    assert args[1] == {"omitted": True, "byte_count": len(b"EXTRA")}
    assert kwargs["label"] == {"omitted": True, "byte_count": len(b"safe")}
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET"),
    }


def test_signature_path_var_positional_named_after_unprotected_table_slot() -> None:
    """Regression:

    ``def write_file(*path, body)`` invoked with the protected body as
    a kwarg. ``*path`` is named after the chio-default ``("path",
    "content")`` table slot ``path`` but ``path`` is NOT a protected
    field. The earlier guard treated ANY VAR_POSITIONAL whose name was
    in the table as a "protected canonical" and skipped the kwonly
    aliasing pass entirely, leaving ``body='PROD_SECRET_DISTINCT'``
    forwarded raw. Only an ACTUAL protected canonical should suppress
    aliasing. Distinct byte length (24) so a future regression cannot
    coincidentally match a matching ``byte_count`` from an unrelated
    redaction.
    """

    def write_file(*path: str, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x",),
        {"body": "PROD_SECRET_DISTINCT_24!"},
        tool_name="chio_file_write",
    )
    assert args == ["/tmp/x"]
    assert kwargs["body"] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_DISTINCT_24!"),
    }


def test_typeerror_fallback_kwonly_only_preserves_default_prefix() -> None:
    """Regression:

    A kwonly-only wrapper has no fixed positional signature slots, but
    the chio default wire table still says position 0 is ``path`` and
    position 1 is ``content``. When an invalid caller supplies two
    positionals, the TypeError fallback must preserve that prefix so
    the path-like first value stays raw and the body-like second value
    redacts under the kwonly alias.
    """

    def write_file(*, body: str) -> None:
        del body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "PROD_SECRET_KWONLY_ONLY"),
        {},
        tool_name="chio_file_write",
    )
    assert kwargs == {}
    assert args[0] == "/tmp/x"
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_KWONLY_ONLY"),
    }


def test_empty_positional_table_does_not_invent_overflow_slot() -> None:
    """No positional map means extra args stay raw.

    Keyword redaction still applies by name, but the fallback must not
    synthesize a protected positional slot when no positional mapping exists.
    """

    def proxy(**kwargs: object) -> None:
        del kwargs

    policy = RedactionPolicy(body_fields={"chio_file_write": ("content",)})
    args, kwargs = bind_and_redact(
        proxy,
        ("PROD_SECRET_NO_POSITIONAL_SLOT",),
        {"content": "KW_SECRET"},
        tool_name="chio_file_write",
        policy=policy,
        positional_table={"chio_file_write": ()},
    )
    assert args == ["PROD_SECRET_NO_POSITIONAL_SLOT"]
    assert kwargs["content"] == {
        "omitted": True,
        "byte_count": len(b"KW_SECRET"),
    }


def test_typeerror_fallback_unprotected_var_positional_keeps_table_prefix() -> None:
    """Regression:

    ``def write_file(*path, body)`` has a VAR_POSITIONAL named after an
    unprotected table slot. An invalid ``path=`` kwarg drives the
    TypeError fallback. That fallback must not treat ``*path`` as a
    protected variadic body; it should preserve the normal table prefix
    and map the second positional to the kwonly body alias.
    """

    def write_file(*path: str, body: str) -> None:
        del path, body

    args, kwargs = bind_and_redact(
        write_file,
        ("/tmp/x", "PROD_SECRET_FROM_SECOND_POSITION"),
        {"path": "/tmp/from-kw"},
        tool_name="chio_file_write",
    )
    assert args[0] == "/tmp/x"
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_FROM_SECOND_POSITION"),
    }
    assert kwargs == {"path": "/tmp/from-kw"}


def test_signature_path_swap_detected_ambiguous_fixed_aliases_redact_all() -> None:
    """Regression:

    ``def write_file(label, body, path)`` invoked positionally. The
    swap-detected branch (``path`` at sig idx 2 vs table idx 0) used
    to greedily assign the only unclaimed protected canonical
    (``content``) to the first-declared unmatched wrapper-name
    (``label``), leaving ``body`` self-aliased so ``body='PROD_SECRET
    _SWAP_BODY'`` forwarded raw at args[1]. The fix mirrors the kwonly
    Pass-B ambiguous-fail-closed: when more unmatched wrappers than
    free canonicals, cycle every unmatched wrapper through the
    protected list. Both args must redact and each stub must report
    ITS OWN byte_count (label: 6 bytes, body: 22 bytes) so a future
    byte-count regression can't hide.
    """

    def write_file(label: str, body: str, path: str) -> None:
        del label, body, path

    args, kwargs = bind_and_redact(
        write_file,
        ("LABEL!", "PROD_SECRET_SWAP_BODY!", "/tmp"),
        {},
        tool_name="chio_file_write",
    )
    assert kwargs == {}
    assert args[0] == {"omitted": True, "byte_count": len(b"LABEL!")}
    assert args[1] == {
        "omitted": True,
        "byte_count": len(b"PROD_SECRET_SWAP_BODY!"),
    }
    assert args[2] == "/tmp"


def test_typeerror_fallback_colliding_positional_aliases_redact_independently() -> None:
    """Regression:

    ``def write_file(label, body, path)`` invoked positionally AND with
    ``path='/tmp'`` as a kwarg triggers ``bind_partial`` TypeError
    (``path`` duplicated across positional + kwarg). The TypeError
    fallback builds an ambiguous-fail-closed alias map sending BOTH
    ``label`` and ``body`` to canonical ``content``. Keying the
    canonical-redact view by canonical name would let the second slot
    silently overwrite the first in the dict view and crash the rebuild
    with a ``KeyError`` on the missing wrapper-name.

    Mirroring the overflow path: when two wrapper slot names collide on
    the same canonical, the second slot routes through a per-position
    sentinel so each value redacts and rebuilds independently. Both
    stubs must report DISTINCT byte_counts (4 != 11) so a regression
    that re-uses one slot's record for both positions cannot hide.
    """

    def write_file(label: str, body: str, path: str) -> None:
        del label, body, path

    args, kwargs = bind_and_redact(
        write_file,
        ("safe", "PROD_SECRET", "/tmp"),
        {"path": "/tmp"},
        tool_name="chio_file_write",
    )
    assert kwargs == {"path": "/tmp"}
    assert args[0] == {"omitted": True, "byte_count": len(b"safe")}
    assert args[1] == {"omitted": True, "byte_count": len(b"PROD_SECRET")}
    assert args[2] == "/tmp"
    # Distinct byte counts guard the per-position keying: if a future
    # regression collapses the two slots onto a single canonical record
    # again, both args[0] and args[1] would report the same byte_count.
    assert args[0]["byte_count"] != args[1]["byte_count"]


def test_build_alias_map_is_importable_from_top_level() -> None:
    """Regression:

    ``build_alias_map`` is a public helper (no underscore prefix) and
    is advertised in the PR description as exposing the wrapper-name
    -> canonical-name routing algorithm. It must be re-exported from
    the top-level ``chio_adapter_base`` namespace so wildcard imports
    and tooling-generated API docs surface it.
    """

    import chio_adapter_base

    assert "build_alias_map" in chio_adapter_base.__all__
    assert hasattr(chio_adapter_base, "build_alias_map")
    # Smoke-test the exposed callable on the swap-detection scenario it
    # handles.
    routing = chio_adapter_base.build_alias_map(
        ("body", "path"),
        ("path", "content"),
        ("content",),
    )
    # Pass-1 self-canonical: ``path`` claims its slot. Pass-2 swap-
    # detected: ``body`` routes to unclaimed protected canonical.
    assert routing == {"path": "path", "body": "content"}
