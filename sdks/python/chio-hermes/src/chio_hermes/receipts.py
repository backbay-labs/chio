"""Receipt buffer + JSONL store for the chio-hermes plugin.

Hermes does not dispatch `tool_call_id` into the handler kwargs; it
only passes `task_id`. The plugin therefore keys pending receipts by
`task_id` alone with FIFO semantics.

The JSONL log at `<hermes_home>/logs/chio-receipts.jsonl` is a
user-side convenience for the active Hermes session, NOT the canonical
audit store. Tamper-evident long-term storage lives in the sidecar's
`--receipts-db`.

The byte-level helpers (``canonical_dumps``, ``append_jsonl``) and the
in-memory queue/deque mechanics live in
:mod:`chio_adapter_base.receipts`; this module is a thin Hermes-aware
wrapper that resolves the JSONL log path from
``HERMES_HOME`` / ``hermes_constants.get_hermes_home`` and keeps the
chio-hermes 0.1.0 surface intact: ``ReceiptBuffer``, ``append_jsonl``,
``_canonical_dumps``, ``_resolve_log_path``,
``DEFAULT_RECEIPT_BUFFER_MAX``. New code should import directly from
``chio_adapter_base.receipts`` when it does not need Hermes path
resolution.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from chio_adapter_base.receipts import (
    DEFAULT_RECEIPT_BUFFER_MAX as _ADAPTER_BASE_DEFAULT_RECEIPT_BUFFER_MAX,
)
from chio_adapter_base.receipts import append_jsonl as _adapter_base_append_jsonl
from chio_adapter_base.receipts import (
    canonical_dumps as _adapter_base_canonical_dumps,
)

_logger = logging.getLogger(__name__)

DEFAULT_RECEIPT_BUFFER_MAX = _ADAPTER_BASE_DEFAULT_RECEIPT_BUFFER_MAX


def _buffer_max() -> int:
    raw = os.environ.get("CHIO_RECEIPT_BUFFER_MAX")
    if not raw:
        return DEFAULT_RECEIPT_BUFFER_MAX
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_RECEIPT_BUFFER_MAX
    return value if value > 0 else DEFAULT_RECEIPT_BUFFER_MAX


def _resolve_log_path() -> Path:
    """Resolve the JSONL log path, lazily importing `hermes_constants`.

    The lazy import keeps Hermes off the package import path so the
    plugin still registers when Hermes is not installed (Path A users).
    """
    try:
        from hermes_constants import get_hermes_home

        home = Path(get_hermes_home())
    except Exception:
        home = Path.home() / ".hermes"
    return home / "logs" / "chio-receipts.jsonl"


def _canonical_dumps(record: dict[str, Any]) -> bytes:
    """Delegates to ``chio_adapter_base.receipts.canonical_dumps``."""
    return _adapter_base_canonical_dumps(record)


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append `record` as one canonical-JSON line. Raises `OSError`.

    Re-export of :func:`chio_adapter_base.receipts.append_jsonl`. New
    code should import from chio-adapter-base directly; the chio-hermes
    name is preserved as the documented public API of this module so
    no deprecation warning fires here. Module-level so existing tests
    can ``monkeypatch.setattr(_receipts, "append_jsonl", capture)`` to
    intercept JSONL writes.
    """
    _adapter_base_append_jsonl(path, record)


class ReceiptBuffer:
    """In-memory buffer + append-only JSONL writer for plugin receipts.

    The pending-queue / recorded-deque / denial-counter mechanics are
    structurally identical to
    :class:`chio_adapter_base.receipts.ReceiptBuffer`. This class kept
    its own implementation (rather than subclassing) because the
    chio-hermes JSONL write path must resolve through the
    module-level :func:`append_jsonl` and :func:`_resolve_log_path`
    so existing tests that ``monkeypatch.setattr(_receipts, ...)``
    AFTER the buffer is constructed still see the override (the base
    class binds its log-path factory at construction time and calls
    its own module-level ``append_jsonl`` directly, which would skip
    the chio-hermes-side monkeypatches).
    """

    def __init__(self, *, buffer_max: int | None = None) -> None:
        self._buffer_max = (
            buffer_max if buffer_max is not None else _buffer_max()
        )
        self._pending: dict[str, deque[dict[str, Any]]] = {}
        self._buffer: deque[dict[str, Any]] = deque(maxlen=self._buffer_max)
        self._denials = 0
        self._lock = threading.Lock()

    def push(self, task_id: str | None, record: dict[str, Any]) -> None:
        """Record a pending receipt entry under `task_id`.

        `task_id` may be `None` because some Hermes paths (e.g. CLI
        smoke calls) do not propagate it; coalesce under a sentinel
        key so `pop_next(None)` still works.
        """
        key = task_id or ""
        with self._lock:
            self._pending.setdefault(key, deque()).append(dict(record))

    def pop_next(self, task_id: str | None) -> dict[str, Any] | None:
        """Pop the oldest pending receipt for `task_id` (FIFO) or `None`."""
        key = task_id or ""
        with self._lock:
            queue = self._pending.get(key)
            if not queue:
                return None
            entry = queue.popleft()
            if not queue:
                self._pending.pop(key, None)
            return entry

    def clear_pending(self) -> None:
        with self._lock:
            self._pending.clear()

    def drain_pending(self) -> Iterator[dict[str, Any]]:
        """Yield and drop every pending entry across all task_ids."""
        with self._lock:
            collected: list[dict[str, Any]] = []
            for queue in self._pending.values():
                collected.extend(queue)
            self._pending.clear()
        yield from collected

    def record(self, receipt: dict[str, Any]) -> None:
        """Append a finalised receipt to the in-memory deque + JSONL log.

        Tolerates JSONL write failures so a transient disk problem
        cannot crash Hermes. The JSONL write happens INSIDE the lock
        so concurrent recorders cannot interleave bytes within a line.
        Module-level :func:`append_jsonl` and :func:`_resolve_log_path`
        are looked up via :data:`sys.modules` on every call so tests
        that ``monkeypatch.setattr`` either symbol after the buffer is
        constructed still see the override.
        """
        with self._lock:
            self._buffer.append(receipt)
            if (
                receipt.get("status") == "denied"
                or receipt.get("error") == "denied"
            ):
                self._denials += 1
            try:
                module = sys.modules[__name__]
                module.append_jsonl(module._resolve_log_path(), receipt)
            except (OSError, TypeError, ValueError) as exc:
                _logger.warning("receipt JSONL write failed: %s", exc)

    def recent(self, n: int = 5) -> list[dict[str, Any]]:
        # `n <= 0` returns nothing: a naive `[-max(0, n):]` slice would
        # evaluate `[0:]` and return the entire buffer, the opposite of
        # what the caller asked for.
        count = int(n)
        if count <= 0:
            return []
        with self._lock:
            return list(self._buffer)[-count:]

    def denial_count(self) -> int:
        with self._lock:
            return self._denials

    def pending_total(self) -> int:
        with self._lock:
            return sum(len(q) for q in self._pending.values())


__all__ = [
    "DEFAULT_RECEIPT_BUFFER_MAX",
    "ReceiptBuffer",
    "_canonical_dumps",
    "_resolve_log_path",
    "append_jsonl",
]
