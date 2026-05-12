"""Shared pytest helpers and fixtures for sibling adapters.

The intent is so that an adapter test like
``chio-langchain/tests/test_conformance.py`` can do::

    pytest_plugins = ["chio_adapter_base.conformance"]

    def test_chio_langchain_conformance(
        adapter_base_fixture: ConformanceFixture,
    ) -> None:
        ...

and inherit a battery of behavioural assertions for every primitive
the adapter wires up. Adapters that want a custom fixture (for example
a non-default redaction policy) instantiate :class:`ConformanceFixture`
directly with overrides instead of using the auto-fixture.

The conformance suite asserts the contract every Chio adapter must
honour:

- :class:`RedactArgs` replaces the configured field with
  ``{"omitted": True, "byte_count": <int>}`` and preserves siblings.
- :class:`ReceiptBuffer` is FIFO per ``task_id`` and increments
  ``denial_count`` on a denied receipt.
- :func:`forbidden_path_filter` partitions correctly.
- :class:`BoundedSubprocess` ``run`` is callable (sanity check; the
  full subprocess test is in ``tests/test_security.py`` because it
  needs the host's ``python`` interpreter).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

import pytest

from chio_adapter_base.filters import forbidden_path_filter
from chio_adapter_base.receipts import ReceiptBuffer
from chio_adapter_base.redact import RedactArgs
from chio_adapter_base.security import BoundedSubprocess


@dataclasses.dataclass
class ConformanceFixture:
    """Bundle of primitive instances for the conformance suite.

    Adapters typically use the auto-instantiated default via the
    ``adapter_base_fixture`` pytest fixture. Adapters with custom
    configuration (for example a non-default redaction policy)
    construct one of these directly.
    """

    bounded_subprocess: BoundedSubprocess
    redact: RedactArgs
    receipts: ReceiptBuffer
    redact_field: str = "content"
    redact_tool: str = "chio_file_write"

    @classmethod
    def default(cls) -> ConformanceFixture:
        """Return a fixture wired to the chio-hermes baseline policy."""
        return cls(
            bounded_subprocess=BoundedSubprocess(),
            redact=RedactArgs(
                {
                    "chio_file_write": ("content",),
                    "chio_file_edit": ("patch",),
                }
            ),
            receipts=ReceiptBuffer(),
        )


@pytest.fixture(name="adapter_base_fixture")
def _adapter_base_fixture() -> ConformanceFixture:
    """Default :class:`ConformanceFixture` for the conformance suite."""
    return ConformanceFixture.default()


def assert_redacts_secrets(
    redact: RedactArgs,
    *,
    tool_name: str,
    secret_field: str,
    secret_value: str = "AKIA-EXAMPLE-SECRET-DO-NOT-LEAK",
    sibling: Mapping[str, str] | None = None,
) -> None:
    """Assert that ``redact`` replaces ``secret_field`` with the omission stub.

    - ``redact(tool_name, args)`` must return a dict.
    - The ``secret_field`` entry must be replaced with
      ``{"omitted": True, "byte_count": <utf8 byte count>}``.
    - All sibling fields must be preserved verbatim.
    """
    args: dict[str, object] = dict(sibling or {"path": "x.txt"})
    args[secret_field] = secret_value

    redacted = redact(tool_name, args)
    assert isinstance(redacted, dict), "redact must return a dict"

    expected_bytes = len(secret_value.encode("utf-8"))
    expected_stub = {"omitted": True, "byte_count": expected_bytes}
    assert redacted.get(secret_field) == expected_stub, (
        f"expected {secret_field} to be {expected_stub!r}, "
        f"got {redacted.get(secret_field)!r}"
    )

    for key, value in (sibling or {"path": "x.txt"}).items():
        assert redacted.get(key) == value, (
            f"sibling field {key!r} was mutated; expected {value!r}, "
            f"got {redacted.get(key)!r}"
        )


def assert_receipts_fifo(buffer: ReceiptBuffer) -> None:
    """Assert :class:`ReceiptBuffer` is FIFO per ``task_id``."""
    buffer.push("task-A", {"i": 1})
    buffer.push("task-A", {"i": 2})
    buffer.push("task-B", {"i": 99})

    assert buffer.pop_next("task-A") == {"i": 1}
    assert buffer.pop_next("task-A") == {"i": 2}
    assert buffer.pop_next("task-A") is None
    assert buffer.pop_next("task-B") == {"i": 99}


def assert_denial_count_increments(buffer: ReceiptBuffer) -> None:
    """Assert ``denial_count`` increments on denied receipts."""
    before = buffer.denial_count()
    buffer.record({"status": "denied"})
    buffer.record({"error": "denied"})
    buffer.record({"status": "allowed"})
    assert buffer.denial_count() == before + 2


def assert_forbidden_path_filter_partitions() -> None:
    """Assert :func:`forbidden_path_filter` partitions and preserves order."""
    kept, dropped = forbidden_path_filter(
        ["a.py", ".env", "b.py", "secrets.key"],
        is_forbidden=lambda p: p in {".env", "secrets.key"},
    )
    assert kept == ["a.py", "b.py"]
    assert dropped == [".env", "secrets.key"]


# Conformance test entry points. Adapters that include this module via
# ``pytest_plugins`` get these tests auto-collected against their
# default fixture.


def test_conformance_redacts_default_field(
    adapter_base_fixture: ConformanceFixture,
) -> None:
    """The bundled :class:`RedactArgs` redacts its declared field."""
    assert_redacts_secrets(
        adapter_base_fixture.redact,
        tool_name=adapter_base_fixture.redact_tool,
        secret_field=adapter_base_fixture.redact_field,
    )


def test_conformance_receipts_fifo(
    adapter_base_fixture: ConformanceFixture,
) -> None:
    """The bundled :class:`ReceiptBuffer` is FIFO per task id."""
    assert_receipts_fifo(adapter_base_fixture.receipts)


def test_conformance_denial_count(
    adapter_base_fixture: ConformanceFixture,
) -> None:
    """The bundled :class:`ReceiptBuffer` counts denials."""
    assert_denial_count_increments(adapter_base_fixture.receipts)


def test_conformance_forbidden_path_filter() -> None:
    """:func:`forbidden_path_filter` partitions and preserves order."""
    assert_forbidden_path_filter_partitions()


__all__ = [
    "ConformanceFixture",
    "assert_denial_count_increments",
    "assert_forbidden_path_filter_partitions",
    "assert_receipts_fifo",
    "assert_redacts_secrets",
]
