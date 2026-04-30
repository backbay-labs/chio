"""Telemetry-free local receipt sink for the fastapi-langchain template.

The TTFRH bench asserts no outbound network calls beyond the explicitly
configured upstream provider. This sink keeps a bounded in-memory ring
buffer; production deployments swap in a durable transport behind the
``ReceiptSink`` protocol.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Protocol


@dataclass(frozen=True)
class Receipt:
    """A single Chio receipt record captured during agent invocation."""

    id: str
    verdict: str
    source: str
    captured_at_iso: str


class ReceiptSink(Protocol):
    """Sink protocol consumed by the FastAPI app and the static viewer."""

    def list(self) -> Iterable[Receipt]:
        """Return the captured receipts in insertion order."""

    def record(self, receipt: Receipt) -> None:
        """Append a new receipt, evicting the oldest beyond capacity."""


class LocalReceiptSink:
    """Bounded in-memory ``ReceiptSink`` with telemetry-free semantics."""

    def __init__(self, capacity: int = 64) -> None:
        self._buffer: Deque[Receipt] = deque(maxlen=capacity)
        self._buffer.append(
            Receipt(
                id="local-template-receipt",
                verdict="allow",
                source="local receipt sink",
                captured_at_iso="1970-01-01T00:00:00Z",
            )
        )

    def list(self) -> Iterable[Receipt]:
        return tuple(self._buffer)

    def record(self, receipt: Receipt) -> None:
        self._buffer.append(receipt)


_SHARED: LocalReceiptSink | None = None


def get_local_receipt_sink() -> LocalReceiptSink:
    """Return the process-wide shared local sink instance."""

    global _SHARED
    if _SHARED is None:
        _SHARED = LocalReceiptSink()
    return _SHARED


def reset_local_receipt_sink_for_testing() -> None:
    """Reset the shared sink. Test-only entry point."""

    global _SHARED
    _SHARED = None
