"""Behavioural tests for :func:`chio_adapter_base.redact.bind_and_redact`."""

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

    Regression for bot comment 3229135384: a fixed-signature custom
    tool (``def my_tool(path, body)``) called with a duplicate
    protected name (``my_tool("p", "SECRET", body="KW")``) caused
    ``bind_partial`` to raise. The fallback used the chio-default
    positional table, which has no entry for ``my_tool``, so the
    positional ``body`` value was returned raw. The fix derives the
    fallback positional names from the signature itself when the
    caller has not supplied a ``positional_table=`` for the tool.
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

    Regression for bot comments 3229375712 and 3229301707: the
    wrapper's varargs parameter is itself the protected field name
    (``content``). Previously, the rebuild loop ignored the declared
    ``*content`` name and bound extras only via the positional
    table. Because ``path`` already filled the table's ``path`` slot
    via kwargs, the first content chunk was treated as ``path`` and
    returned raw.
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

    Regression for bot comments 3229301699 and 3229411436:
    Python permits both a positional-only ``path`` and a
    same-named entry in ``**kw``. ``bind_partial`` keeps the
    kwarg in the VAR_KEYWORD spillover, but the rebuild loop
    previously matched ``redacted_fixed`` first and replaced the
    spillover value with the positional value. Each redacted
    independently; the original wire shape preserves both.
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

    Regression for PR #666 P1 (3229550950): when a wrapper for a
    chio-default tool uses a non-canonical parameter name (here
    ``def write_file(path, body)`` against ``chio_file_write`` whose
    canonical slots are ``("path", "content")``), the rebuild must
    route the value through the table-derived canonical name so the
    policy lookup matches. Previously the wrapper's ``body`` name was
    used directly and ``content``-keyed policy missed it, leaking the
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

    Regression for PR #666 P1 (3229550957): a pure-forwarding wrapper
    (``def proxy(*args, **kwargs)``) registered as ``chio_file_write``
    called as ``proxy("PROD_SECRET", path="/tmp/x")``. The kwarg already
    fills slot 0 (``path``), so the lone positional value is logically
    the ``content`` slot. Previously the fallback always mapped
    positional[0] -> table slot 0, returning the raw secret under
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
