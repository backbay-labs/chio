"""Receipt buffer + JSONL store for the chio-hermes plugin.

Hermes does NOT dispatch `tool_call_id` into the handler kwargs; it
only passes `task_id`. The plugin therefore keys pending receipts by
`task_id` alone with FIFO semantics: callers `push` an entry under a
task and `pop_next` it back in the order it arrived.

The JSONL log at `<hermes_home>/logs/chio-receipts.jsonl` is a
user-side convenience for the active Hermes session, NOT the canonical
audit store. Tamper-evident long-term storage lives in the sidecar's
`--receipts-db`. We surface the convenience log so `/chio receipts`
can answer "what did this session see" without an extra round-trip.
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
"""Default cap on the in-memory deque length (per `CHIO_RECEIPT_BUFFER_MAX`)."""


def _buffer_max() -> int:
    """Read `CHIO_RECEIPT_BUFFER_MAX` lazily so tests can vary it."""
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
    Falls back to `~/.hermes/logs/chio-receipts.jsonl` when
    `hermes_constants.get_hermes_home` is not importable.
    """
    try:
        from hermes_constants import get_hermes_home

        home = Path(get_hermes_home())
    except Exception:
        home = Path.home() / ".hermes"
    return home / "logs" / "chio-receipts.jsonl"


def _canonical_dumps(record: dict[str, Any]) -> bytes:
    """Serialise a receipt as canonical JSON bytes.

    Sorted keys, no whitespace, UTF-8. Mirrors the `_canonical_json`
    helper in chio-sdk-python so the JSONL line is byte-identical to
    what other adapters log.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append `record` as one canonical-JSON line to `path`.

    Raises `OSError` on disk failure so callers can decide how to handle
    it. `ReceiptBuffer.record` wraps this with suppression for the
    production path; direct unit tests can probe the raising behaviour.
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

    # ------------------------------------------------------------------
    # Pending receipts (push pre-call, pop_next post-call)
    # ------------------------------------------------------------------

    def push(self, task_id: str | None, record: dict[str, Any]) -> None:
        """Record a pending receipt entry under `task_id`.

        `task_id` is allowed to be `None` because some Hermes paths
        (e.g. CLI smoke calls) do not propagate it; we coalesce those
        under a sentinel key so `pop_next(None)` still works.
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
        """Drop every pending entry (used by `on_session_start`)."""
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

    # ------------------------------------------------------------------
    # Recorded receipts (in-memory deque + JSONL append)
    # ------------------------------------------------------------------

    def record(self, receipt: dict[str, Any]) -> None:
        """Append a finalised receipt to the in-memory deque + JSONL log.

        Tolerates JSONL write failures: errors are logged to stderr but
        never raised so a transient disk problem cannot crash Hermes.
        The JSONL write happens INSIDE the lock so concurrent recorders
        cannot interleave bytes within a line.
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

    # ------------------------------------------------------------------
    # Introspection helpers used by `/chio` slash commands
    # ------------------------------------------------------------------

    def recent(self, n: int = 5) -> list[dict[str, Any]]:
        """Return up to `n` most recent recorded receipts."""
        with self._lock:
            return list(self._buffer)[-max(0, int(n)) :]

    def denial_count(self) -> int:
        """Return the running count of recorded denials."""
        with self._lock:
            return self._denials

    def pending_total(self) -> int:
        """Return the total number of pending entries across all tasks."""
        with self._lock:
            return sum(len(q) for q in self._pending.values())


__all__ = [
    "DEFAULT_RECEIPT_BUFFER_MAX",
    "ReceiptBuffer",
    "_canonical_dumps",
    "_resolve_log_path",
    "append_jsonl",
]
