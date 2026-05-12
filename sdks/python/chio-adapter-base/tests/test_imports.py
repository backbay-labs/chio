"""Smoke test: the documented public API surface imports cleanly.

This is the Phase 1 acceptance test. It verifies the contract in
``README.md`` and ``.planning/chio-adapter-base/PLAN.md`` section 3
without requiring any of the primitives to be implemented yet. Phase 2
adds per-primitive behaviour tests; this test continues to gate any
accidental rename or missing re-export.
"""

from __future__ import annotations

import pytest


def test_top_level_convenience_imports() -> None:
    """The convenience aliases in ``chio_adapter_base.__init__`` resolve."""
    import chio_adapter_base

    expected_names = {
        "DEFAULT_RECEIPT_BUFFER_MAX",
        "DEFAULT_SHELL_TIMEOUT",
        "DEFAULT_SUBPROCESS_MAX_BYTES",
        "BoundedSubprocess",
        "BoundedSubprocessResult",
        "ReceiptBuffer",
        "RedactionPolicy",
        "__version__",
        "append_jsonl",
        "forbidden_path_filter",
        "harden_git_argv",
        "redact_args",
        "reject_shell_argv_escape",
        "sanitised_env",
    }
    assert expected_names.issubset(set(chio_adapter_base.__all__))
    for name in expected_names:
        assert hasattr(chio_adapter_base, name), f"missing top-level {name!r}"


def test_security_submodule_surface() -> None:
    from chio_adapter_base import security

    for name in (
        "DEFAULT_SHELL_TIMEOUT",
        "DEFAULT_SUBPROCESS_MAX_BYTES",
        "BoundedSubprocess",
        "BoundedSubprocessResult",
        "harden_git_argv",
        "reject_shell_argv_escape",
        "sanitised_env",
    ):
        assert hasattr(security, name), f"missing security.{name!r}"


def test_receipts_submodule_surface() -> None:
    from chio_adapter_base import receipts

    for name in (
        "DEFAULT_RECEIPT_BUFFER_MAX",
        "ReceiptBuffer",
        "append_jsonl",
    ):
        assert hasattr(receipts, name), f"missing receipts.{name!r}"


def test_redact_submodule_surface() -> None:
    from chio_adapter_base import redact

    for name in ("RedactionPolicy", "redact_args"):
        assert hasattr(redact, name), f"missing redact.{name!r}"


def test_filters_submodule_surface() -> None:
    from chio_adapter_base import filters

    assert hasattr(filters, "forbidden_path_filter")


def test_conformance_submodule_present_but_empty() -> None:
    """Phase 1 conformance namespace ships empty; tests will populate it."""
    from chio_adapter_base import conformance

    assert isinstance(conformance.__all__, list)
    assert conformance.__all__ == []


def test_primitives_raise_not_implemented_in_phase_one() -> None:
    """Each primitive raises ``NotImplementedError`` until Phase 2 ports it.

    This protects against an accidental partial implementation slipping
    into a Phase 1 release. Phase 2 will delete this test (or invert it
    to assert a real return shape).
    """
    import pathlib

    from chio_adapter_base import (
        BoundedSubprocess,
        ReceiptBuffer,
        RedactionPolicy,
        append_jsonl,
        forbidden_path_filter,
        harden_git_argv,
        redact_args,
        reject_shell_argv_escape,
        sanitised_env,
    )

    with pytest.raises(NotImplementedError):
        sanitised_env()
    with pytest.raises(NotImplementedError):
        harden_git_argv(["git", "commit", "-m", "x"])
    with pytest.raises(NotImplementedError):
        reject_shell_argv_escape("ls", root=pathlib.Path("/tmp"))
    with pytest.raises(NotImplementedError):
        BoundedSubprocess().run(["echo", "x"], cwd=pathlib.Path("/tmp"))
    with pytest.raises(NotImplementedError):
        append_jsonl(pathlib.Path("/tmp/x.jsonl"), {"k": "v"})
    with pytest.raises(NotImplementedError):
        ReceiptBuffer().push(None, {})
    with pytest.raises(NotImplementedError):
        RedactionPolicy.chio_default()
    with pytest.raises(NotImplementedError):
        redact_args("chio_file_write", {"content": "x"})
    with pytest.raises(NotImplementedError):
        forbidden_path_filter([], is_forbidden=lambda _p: False)
