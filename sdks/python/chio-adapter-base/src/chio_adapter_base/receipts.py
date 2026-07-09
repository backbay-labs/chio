"""In-memory receipt buffer + JSONL append for Chio adapters.

This module hosts:

- :class:`ReceiptBuffer`: thread-safe in-memory FIFO with per-``task_id``
  pending queues and a bounded recorded-receipt deque. Source of truth:
  ``ReceiptBuffer`` in
  ``sdks/python/chio-hermes/src/chio_hermes/receipts.py:79``.

- :func:`append_jsonl`: append one canonical-JSON line atomically. Source
  of truth: ``append_jsonl`` in
  ``sdks/python/chio-hermes/src/chio_hermes/receipts.py:65``.

- :func:`canonical_dumps`: serialise a record as canonical-JSON bytes
  (sorted keys, no whitespace, ASCII-safe). Mirrors
  ``_canonical_dumps`` from chio-hermes.

Adapters that have a different receipt shape (chio-streaming's broker
envelope, chio-temporal's workflow aggregator) intentionally do NOT
use :class:`ReceiptBuffer`; they keep their own envelope.
:class:`ReceiptBuffer` is for adapters whose host process needs to
buffer per-tool receipts before flushing to the sidecar / local JSONL
log.
"""

from __future__ import annotations

import json
import logging
import pathlib
import threading
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from typing import Any

DEFAULT_RECEIPT_BUFFER_MAX: int = 1000
"""Mirror of ``chio_hermes.receipts.DEFAULT_RECEIPT_BUFFER_MAX``."""

_logger = logging.getLogger(__name__)


def canonical_dumps(record: Mapping[str, Any]) -> bytes:
    """Serialise ``record`` as canonical JSON bytes.

    Sorted keys, no whitespace, ASCII-safe. Mirrors ``_canonical_dumps``
    in ``chio_hermes.receipts``; the resulting bytes are byte-identical
    to chio-sdk-python's ``_canonical_json``.
    """
    return json.dumps(
        dict(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def append_jsonl(path: pathlib.Path, record: Mapping[str, Any]) -> None:
    """Append ``record`` as one canonical-JSON line, atomically.

    Single ``fh.write`` of canonical-JSON bytes plus newline. POSIX
    append-mode is atomic per write up to ``PIPE_BUF`` (~4 KiB on
    Linux), so a single write keeps the line whole even if the process
    is killed mid-write. Creates parent directories on demand.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_dumps(record) + b"\n"
    with path.open("ab") as fh:
        fh.write(payload)


class ReceiptBuffer:
    """In-memory buffer + append-only JSONL writer for adapter receipts.

    Thread-safe via a single ``threading.Lock``; the JSONL write happens
    inside the lock so concurrent recorders cannot interleave bytes
    within a line.

    Args:
      buffer_max: bound on the recorded-receipt deque. Oldest entries
        drop first when the cap is exceeded. Defaults to
        :data:`DEFAULT_RECEIPT_BUFFER_MAX`.
      log_path_factory: callable returning the JSONL log path. ``None``
        disables JSONL writes (in-memory only). Adapters that want to
        persist should pass a factory that returns the desired path;
        the factory is called once per :meth:`record` so the path can
        rotate with environment changes.
    """

    def __init__(
        self,
        *,
        buffer_max: int | None = None,
        log_path_factory: Callable[[], pathlib.Path] | None = None,
    ) -> None:
        self._buffer_max = (
            buffer_max if buffer_max is not None else DEFAULT_RECEIPT_BUFFER_MAX
        )
        self._log_path_factory = log_path_factory
        self._pending: dict[str, deque[dict[str, Any]]] = {}
        self._buffer: deque[dict[str, Any]] = deque(maxlen=self._buffer_max)
        self._denials = 0
        self._lock = threading.Lock()

    def push(self, task_id: str | None, record: Mapping[str, Any]) -> None:
        """Push a pending receipt under ``task_id``.

        ``task_id`` may be ``None``; pending entries without a task id
        are coalesced under the empty-string sentinel so
        ``pop_next(None)`` still works.
        """
        key = task_id or ""
        with self._lock:
            self._pending.setdefault(key, deque()).append(dict(record))

    def pop_next(self, task_id: str | None) -> dict[str, Any] | None:
        """Pop the oldest pending receipt for ``task_id`` (FIFO) or ``None``."""
        key = task_id or ""
        with self._lock:
            queue = self._pending.get(key)
            if not queue:
                return None
            entry = queue.popleft()
            if not queue:
                self._pending.pop(key, None)
            return entry

    def clear_pending(self, task_id: str | None = None) -> None:
        """Drop pending entries.

        With ``task_id=None`` (default), drops every pending entry
        across all queues. With a specific ``task_id``, drops only that
        queue.
        """
        with self._lock:
            if task_id is None:
                self._pending.clear()
            else:
                self._pending.pop(task_id, None)

    def drain_pending(
        self, task_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Yield-and-drop every pending entry for ``task_id`` (or all).

        Returns a materialised list (not an iterator) so the caller can
        operate without holding the lock. Mirrors
        ``chio_hermes.receipts.ReceiptBuffer.drain_pending`` but with
        the per-``task_id`` filter the user spec asks for.
        """
        with self._lock:
            collected: list[dict[str, Any]] = []
            if task_id is None:
                for queue in self._pending.values():
                    collected.extend(queue)
                self._pending.clear()
            elif task_id in self._pending:
                collected.extend(self._pending.pop(task_id))
        return collected

    def record(self, receipt: Mapping[str, Any]) -> None:
        """Append a finalised receipt to the in-memory deque + JSONL log.

        Tolerates JSONL write failures so a transient disk problem
        cannot crash the host. ``denial_count`` increments when
        ``status == "denied"`` or ``error == "denied"`` at the top level
        of the receipt.
        """
        record_copy = dict(receipt)
        with self._lock:
            self._buffer.append(record_copy)
            if (
                record_copy.get("status") == "denied"
                or record_copy.get("error") == "denied"
            ):
                self._denials += 1
            if self._log_path_factory is not None:
                try:
                    append_jsonl(self._log_path_factory(), record_copy)
                except (OSError, TypeError, ValueError) as exc:
                    _logger.warning("receipt JSONL write failed: %s", exc)

    def recent(self, n: int = 5) -> list[dict[str, Any]]:
        """Return the ``n`` most recently recorded receipts.

        ``n <= 0`` returns ``[]`` (not the entire buffer): a naive
        ``[-max(0, n):]`` slice would evaluate ``[0:]`` and return
        everything, the opposite of what the caller asked for.
        """
        count = int(n)
        if count <= 0:
            return []
        with self._lock:
            return list(self._buffer)[-count:]

    def denial_count(self) -> int:
        """Total receipts recorded with denied status / error."""
        with self._lock:
            return self._denials

    def pending_total(self) -> int:
        """Total pending entries across all ``task_id`` queues."""
        with self._lock:
            return sum(len(q) for q in self._pending.values())

    # Iterator-style alias kept for chio-hermes parity. The chio-hermes
    # signature returns ``Iterator[dict]``; the new spec asks for a
    # list. Provide both via this helper.
    def iter_drain_pending(self) -> Iterator[dict[str, Any]]:
        """Backwards-compatible iterator over ``drain_pending()``."""
        yield from self.drain_pending()


__all__ = [
    "DEFAULT_RECEIPT_BUFFER_MAX",
    "ReceiptBuffer",
    "append_jsonl",
    "canonical_dumps",
]
