"""Smoke tests for :mod:`chio_adapter_base.conformance`.

This file asserts the conformance module ships an importable fixture
and that the bundled assertions pass against a default instance.
Sibling adapters (chio-langchain, etc.) typically include
``chio_adapter_base.conformance`` as a pytest plugin so the parametrized
tests in that module run against their own configured fixtures.
"""

from __future__ import annotations

from chio_adapter_base.conformance import (
    ConformanceFixture,
    assert_denial_count_increments,
    assert_forbidden_path_filter_partitions,
    assert_receipts_fifo,
    assert_redacts_secrets,
)


def test_default_fixture_constructs() -> None:
    fixture = ConformanceFixture.default()
    assert fixture.bounded_subprocess is not None
    assert fixture.redact is not None
    assert fixture.receipts is not None
    assert fixture.redact_field == "content"
    assert fixture.redact_tool == "chio_file_write"


def test_default_fixture_passes_redaction_assertion() -> None:
    fixture = ConformanceFixture.default()
    assert_redacts_secrets(
        fixture.redact,
        tool_name=fixture.redact_tool,
        secret_field=fixture.redact_field,
    )


def test_default_fixture_passes_receipts_fifo_assertion() -> None:
    fixture = ConformanceFixture.default()
    assert_receipts_fifo(fixture.receipts)


def test_default_fixture_passes_denial_count_assertion() -> None:
    fixture = ConformanceFixture.default()
    assert_denial_count_increments(fixture.receipts)


def test_forbidden_path_filter_assertion_runs() -> None:
    assert_forbidden_path_filter_partitions()


def test_custom_fixture_overrides_redact_field() -> None:
    from chio_adapter_base.receipts import ReceiptBuffer
    from chio_adapter_base.redact import RedactArgs
    from chio_adapter_base.security import BoundedSubprocess

    fixture = ConformanceFixture(
        bounded_subprocess=BoundedSubprocess(),
        redact=RedactArgs({"my_tool": ("body",)}),
        receipts=ReceiptBuffer(),
        redact_field="body",
        redact_tool="my_tool",
    )
    assert_redacts_secrets(
        fixture.redact,
        tool_name=fixture.redact_tool,
        secret_field=fixture.redact_field,
    )
