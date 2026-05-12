"""Behavioural tests for :func:`chio_adapter_base.redact.bind_and_redact`.

Covers the eight branches the helper has to handle so sibling adapters
can replace their inline ``_build_redacted_parameters`` /
``_redact_method_call`` / ``_task_parameters`` equivalents:

1. ``fn=None`` fallback to the positional-name table.
2. C-extension callable (non-introspectable) fallback.
3. Pure forwarding wrapper (``def f(*args, **kwargs)``) fallback.
4. Fixed signature: positional preservation.
5. ``VAR_POSITIONAL`` extras stay positional and unredacted (documented
   limitation; protected fields should not flow through ``*args``).
6. ``VAR_KEYWORD`` spillover redaction.
7. ``drop_self=True`` with a non-self receiver name.
8. Merge conflict (positional and kwarg with the same name) and custom
   ``positional_table`` overrides.
"""

from __future__ import annotations

import inspect

import pytest

from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
)

# ---------------------------------------------------------------------------
# Fallback paths (no introspectable signature)
# ---------------------------------------------------------------------------


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
    """Non-introspectable callables (e.g. builtins) fall back to the table.

    ``dict.update`` is a stand-in: it raises ``ValueError`` from
    :func:`inspect.signature` on the Python versions this package
    supports. Guard the assumption so a future Python that introspects
    every builtin does not silently pass this test.
    """
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
    # No signature/table mapping for the positional value -> stays raw.
    assert args == ["positional-secret"]
    # kwargs path still resolves the chio_file_write -> ("content",) policy.
    assert kwargs["content"] == {"omitted": True, "byte_count": 12}


# ---------------------------------------------------------------------------
# Fixed signature paths
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# VAR_POSITIONAL / VAR_KEYWORD edge cases
# ---------------------------------------------------------------------------


def test_bind_and_redact_var_positional_extras_unredacted() -> None:
    """Extras into ``*args`` have no name; they stay positional and raw.

    This is a documented limitation: the wire shape for protected fields
    must not flow through ``*args``. We assert the unredacted-passthrough
    behaviour so a future change to the contract trips this test.
    """

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

    # ``content`` is not a declared param; it spills into rest. The
    # spillover is re-redacted so the protected field is still covered.
    args, kwargs = bind_and_redact(
        some_wrapper,
        ("src/main.py",),
        {"content": "SECRET\n", "other": "ok"},
        tool_name="chio_file_write",
    )
    assert args == ["src/main.py"]
    assert kwargs["content"] == {"omitted": True, "byte_count": 7}
    assert kwargs["other"] == "ok"


# ---------------------------------------------------------------------------
# drop_self
# ---------------------------------------------------------------------------


def test_bind_and_redact_drop_self_with_non_self_receiver() -> None:
    """``drop_self=True`` skips the first positional regardless of its name.

    The receiver here is named ``this``, not ``self``; ``drop_self``
    still removes it so the remaining positional can be bound to
    ``content`` for redaction.
    """

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
    # Receiver stays at position 0 in the wire shape (we only adjust the
    # signature for binding; we don't reshape the caller's positional
    # list).
    assert args[0] is receiver
    assert args[1] == "src/main.py"
    assert args[2] == {"omitted": True, "byte_count": 7}


# ---------------------------------------------------------------------------
# Merge conflict + custom table
# ---------------------------------------------------------------------------


def test_bind_and_redact_merge_conflict_redacts_both_positions() -> None:
    """Same name in positional and kwargs: redact both; let TypeError surface.

    The wire shape preserves both occurrences; the helper does not
    re-validate Python's arity rules. Callers that care about the
    duplicate get the natural TypeError when they actually invoke ``fn``.
    """

    def chio_file_write(path: str, content: str) -> None:
        del path, content

    args, kwargs = bind_and_redact(
        chio_file_write,
        ("src/main.py", "POSITIONAL-SECRET"),
        # Duplicate ``content`` as a kwarg.
        {"content": "KWARG-SECRET"},
        tool_name="chio_file_write",
    )
    # Positional content is redacted in-place.
    assert args[0] == "src/main.py"
    assert args[1] == {"omitted": True, "byte_count": 17}
    # Kwarg content is still present and also redacted.
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


# ---------------------------------------------------------------------------
# Sanity checks on the public table
# ---------------------------------------------------------------------------


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
