"""Smoke test: the documented public API surface imports cleanly.

Pins every name in the public ``__all__`` to a real callable / class so
an accidental rename or missing re-export shows up immediately.
Per-primitive behaviour tests live in ``test_security.py``,
``test_receipts.py``, etc.
"""

from __future__ import annotations


def test_top_level_convenience_imports() -> None:
    """The convenience aliases in ``chio_adapter_base.__init__`` resolve."""
    import chio_adapter_base

    expected_names = {
        "DEFAULT_RECEIPT_BUFFER_MAX",
        "DEFAULT_SHELL_TIMEOUT",
        "DEFAULT_SUBPROCESS_MAX_BYTES",
        "BoundedSubprocess",
        "BoundedSubprocessResult",
        "ChioPathEscapeError",
        "ReceiptBuffer",
        "RedactArgs",
        "RedactionPolicy",
        "__version__",
        "append_jsonl",
        "build_alias_map",
        "canonical_dumps",
        "filter_diff_output",
        "filter_directory_entries",
        "filter_status_output",
        "forbidden_path_filter",
        "harden_git_argv",
        "redact_args",
        "reject_shell_argv_escape",
        "resolve_within",
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
        "ChioPathEscapeError",
        "harden_git_argv",
        "reject_shell_argv_escape",
        "resolve_within",
        "sanitised_env",
    ):
        assert hasattr(security, name), f"missing security.{name!r}"


def test_receipts_submodule_surface() -> None:
    from chio_adapter_base import receipts

    for name in (
        "DEFAULT_RECEIPT_BUFFER_MAX",
        "ReceiptBuffer",
        "append_jsonl",
        "canonical_dumps",
    ):
        assert hasattr(receipts, name), f"missing receipts.{name!r}"


def test_redact_submodule_surface() -> None:
    from chio_adapter_base import redact

    for name in (
        "RedactArgs",
        "RedactionPolicy",
        "bind_and_redact",
        "build_alias_map",
        "redact_args",
    ):
        assert hasattr(redact, name), f"missing redact.{name!r}"


def test_filters_submodule_surface() -> None:
    from chio_adapter_base import filters

    for name in (
        "filter_diff_output",
        "filter_directory_entries",
        "filter_status_output",
        "forbidden_path_filter",
    ):
        assert hasattr(filters, name), f"missing filters.{name!r}"


def test_conformance_submodule_exports_fixture() -> None:
    """The conformance namespace ships the :class:`ConformanceFixture`."""
    from chio_adapter_base import conformance

    assert "ConformanceFixture" in conformance.__all__
    assert hasattr(conformance, "ConformanceFixture")
    fixture = conformance.ConformanceFixture.default()
    assert fixture.bounded_subprocess is not None
    assert fixture.redact is not None
    assert fixture.receipts is not None
