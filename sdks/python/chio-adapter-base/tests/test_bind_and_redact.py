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
    """Extras into ``*args`` have no name; they stay positional and raw."""

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
    assert args[2:] == ["extra1", "extra2"]
    assert kwargs == {}


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
