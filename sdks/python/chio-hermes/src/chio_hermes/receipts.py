"""Receipt buffer + JSONL store for the chio-hermes plugin.

Hermes does not dispatch `tool_call_id` into the handler kwargs; it
only passes `task_id`. The plugin therefore keys pending receipts by
`task_id` alone with FIFO semantics.

The JSONL log at `<hermes_home>/logs/chio-receipts.jsonl` is a
user-side convenience for the active Hermes session, NOT the canonical
audit store. Tamper-evident long-term storage lives in the sidecar's
`--receipts-db`.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DEFAULT_RECEIPT_BUFFER_MAX = 1000


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
    """Serialise a receipt as canonical JSON bytes.

    Sorted keys, no whitespace, UTF-8. Mirrors `_canonical_json` in
    chio-sdk-python so the JSONL line is byte-identical to other
    adapter logs.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append `record` as one canonical-JSON line to `path`.

    Raises `OSError` on disk failure. `ReceiptBuffer.record` wraps this
    with suppression for the production path; direct callers can probe
    the raising behaviour.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        fh.write(_canonical_dumps(record))
        fh.write(b"\n")


class ReceiptBuffer:
    """In-memory buffer + append-only JSONL writer for plugin receipts.

    Thread-safe via a single `threading.Lock`; Hermes dispatches tools
    on a worker thread so the lock prevents interleaved JSONL writes.
    """

    def __init__(self, *, buffer_max: int | None = None) -> None:
        self._buffer_max = buffer_max if buffer_max is not None else _buffer_max()
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
        cannot crash Hermes. The JSONL write happens INSIDE the lock so
        concurrent recorders cannot interleave bytes within a line.
        """
        with self._lock:
            self._buffer.append(receipt)
            if receipt.get("status") == "denied" or receipt.get("error") == "denied":
                self._denials += 1
            try:
                append_jsonl(_resolve_log_path(), receipt)
            except OSError as exc:
                print(
                    f"[chio-hermes] receipt JSONL write failed: {exc}",
                    file=sys.stderr,
                )

    def recent(self, n: int = 5) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)[-max(0, int(n)) :]

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
