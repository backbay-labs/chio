"""In-memory receipt buffer + JSONL append for Chio adapters.

This module is the future home of:

- ``ReceiptBuffer``: thread-safe in-memory FIFO with per-``task_id``
  pending queues and a bounded recorded-receipt deque. Source of
  truth: ``ReceiptBuffer`` in
  ``sdks/python/chio-hermes/src/chio_hermes/receipts.py:79``.

- ``append_jsonl``: append one canonical-JSON line atomically. Source
  of truth: ``append_jsonl`` in
  ``sdks/python/chio-hermes/src/chio_hermes/receipts.py:65``.

Adapters that have a different receipt shape (chio-streaming's broker
envelope, chio-temporal's workflow aggregator) intentionally do NOT
use ``ReceiptBuffer``; they keep their own envelope. ``ReceiptBuffer``
is for adapters whose host process needs to buffer per-tool receipts
before flushing to the sidecar / local JSONL log.
"""

from __future__ import annotations

import pathlib
from collections.abc import Callable, Iterator, Mapping
from typing import Any

DEFAULT_RECEIPT_BUFFER_MAX: int = 1000
"""Mirror of ``chio_hermes.receipts.DEFAULT_RECEIPT_BUFFER_MAX``."""


def append_jsonl(path: pathlib.Path, record: Mapping[str, Any]) -> None:
    """Append ``record`` as one canonical-JSON line, atomically.

    Single ``fh.write`` of canonical-JSON bytes plus newline. POSIX
    append-mode is atomic per write up to ``PIPE_BUF`` (~4 KiB on
    Linux), so a single write keeps the line whole even if the process
    is killed mid-write. Source of truth:
    ``chio_hermes.receipts.append_jsonl``.
    """
    _ = (path, record)
    raise NotImplementedError(
        "Phase 2: port from chio_hermes.receipts.append_jsonl"
    )


class ReceiptBuffer:
    """In-memory buffer + JSONL writer for adapter receipts.

    Phase 2 port of ``chio_hermes.receipts.ReceiptBuffer``. The
    behaviour contract this scaffold pins:

    - Thread-safe via a single ``threading.Lock``.
    - Pending entries are FIFO per ``task_id``. ``task_id=None`` is
      coalesced under a sentinel key so callers without task ids
      still work.
    - Recorded receipts are appended to a bounded ``deque`` (oldest
      drops first when ``buffer_max`` is exceeded).
    - ``record`` increments ``denial_count`` when
      ``status == "denied"`` or ``error == "denied"`` at the top level
      of the receipt dict.
    - ``record`` writes to a JSONL log via :func:`append_jsonl`. JSONL
      write failures must NOT crash the caller; they are caught,
      logged to stderr, and swallowed.
    - ``log_path_factory`` is the override hook for tests and for
      adapters that want a different log location than chio-hermes's
      ``<hermes_home>/logs/chio-receipts.jsonl``. When ``None``, Phase 2
      lazily resolves the chio-hermes default.
    """

    def __init__(
        self,
        *,
        buffer_max: int | None = None,
        log_path_factory: Callable[[], pathlib.Path] | None = None,
    ) -> None:
        self._buffer_max = buffer_max
        self._log_path_factory = log_path_factory

    def push(self, task_id: str | None, record: Mapping[str, Any]) -> None:
        """Push a pending receipt under ``task_id``."""
        _ = (task_id, record)
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def pop_next(self, task_id: str | None) -> dict[str, Any] | None:
        """Pop the oldest pending receipt for ``task_id`` (FIFO) or ``None``."""
        _ = task_id
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def clear_pending(self) -> None:
        """Drop every pending entry across all ``task_id`` queues."""
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def drain_pending(self) -> Iterator[dict[str, Any]]:
        """Yield and drop every pending entry across all ``task_id`` queues."""
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def record(self, receipt: Mapping[str, Any]) -> None:
        """Append a finalised receipt to the buffer + JSONL log."""
        _ = receipt
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def recent(self, n: int = 5) -> list[dict[str, Any]]:
        """Return the ``n`` most recently recorded receipts.

        ``n <= 0`` returns ``[]``. The chio-hermes implementation has a
        well-known bug fix here: the historical ``[-max(0, n):]``
        evaluated ``[0:]`` and returned the entire buffer (the opposite
        of what the caller asked for). The conformance test asserts the
        ``n=0`` case is empty.
        """
        _ = n
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def denial_count(self) -> int:
        """Total receipts recorded with denied status / error."""
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")

    def pending_total(self) -> int:
        """Total pending entries across all ``task_id`` queues."""
        raise NotImplementedError("Phase 2: port from chio_hermes.receipts")


__all__ = [
    "DEFAULT_RECEIPT_BUFFER_MAX",
    "ReceiptBuffer",
    "append_jsonl",
]
