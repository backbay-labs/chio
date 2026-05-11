"""ReceiptBuffer + JSONL writer behaviour.

The receipts module owns three contracts:

1. **FIFO order** -- `push` then `pop_next` for the same `task_id`
   returns records in the order they were pushed (Hermes parallel
   tools share a `task_id`).
2. **Canonical JSON on disk** -- `append_jsonl` writes one JSON Lines
   entry per call, with sorted keys, no whitespace, ASCII-safe
   encoding.
3. **Suppression boundary** -- `record` swallows OSError so a transient
   disk problem cannot crash Hermes; `append_jsonl` itself raises so
   direct callers can decide.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from chio_hermes.receipts import (
    DEFAULT_RECEIPT_BUFFER_MAX,
    ReceiptBuffer,
    _canonical_dumps,
    _resolve_log_path,
    append_jsonl,
)

# ---------------------------------------------------------------------------
# FIFO push / pop_next
# ---------------------------------------------------------------------------


def test_push_pop_fifo_order() -> None:
    buf = ReceiptBuffer()
    for i in range(5):
        buf.push("task-A", {"i": i})

    seen = [buf.pop_next("task-A") for _ in range(5)]
    assert [r["i"] for r in seen] == [0, 1, 2, 3, 4]


def test_pop_isolates_per_task() -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"i": 1})
    buf.push("task-B", {"i": 2})
    assert buf.pop_next("task-A") == {"i": 1}
    assert buf.pop_next("task-B") == {"i": 2}


def test_pop_when_empty_returns_none() -> None:
    buf = ReceiptBuffer()
    assert buf.pop_next("no-such-task") is None


def test_drain_pending_yields_and_clears() -> None:
    buf = ReceiptBuffer()
    buf.push("task-A", {"i": 1})
    buf.push("task-B", {"i": 2})
    drained = list(buf.drain_pending())
    assert len(drained) == 2
    assert buf.pending_total() == 0


# ---------------------------------------------------------------------------
# Canonical JSON on disk
# ---------------------------------------------------------------------------


def test_append_jsonl_writes_canonical_json(tmp_path: Path) -> None:
    log_path = tmp_path / "chio-receipts.jsonl"
    payload = {"z": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    append_jsonl(log_path, payload)

    raw = log_path.read_text(encoding="utf-8")
    line = raw.rstrip("\n")
    assert line == '{"a":2,"nested":{"x":2,"y":1},"z":1}'
    assert json.loads(line) == payload


def test_append_jsonl_appends_one_line_per_call(tmp_path: Path) -> None:
    log_path = tmp_path / "chio-receipts.jsonl"
    append_jsonl(log_path, {"id": "rcpt-1"})
    append_jsonl(log_path, {"id": "rcpt-2"})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == "rcpt-1"
    assert json.loads(lines[1])["id"] == "rcpt-2"


def test_canonical_dumps_helper_is_byte_stable() -> None:
    out = _canonical_dumps({"b": 2, "a": 1})
    assert out == b'{"a":1,"b":2}'


# ---------------------------------------------------------------------------
# Buffer cap
# ---------------------------------------------------------------------------


def test_buffer_cap_uses_default() -> None:
    buf = ReceiptBuffer()
    # Default cap applies to the recorded buffer (deque maxlen).
    for i in range(DEFAULT_RECEIPT_BUFFER_MAX + 5):
        buf._buffer.append({"i": i})  # type: ignore[attr-defined]
    assert len(buf._buffer) == DEFAULT_RECEIPT_BUFFER_MAX  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# File-IO failure behaviour
# ---------------------------------------------------------------------------


def test_append_jsonl_propagates_oserror(tmp_path: Path) -> None:
    """The free function must raise OSError so callers can decide."""
    bad_path = tmp_path / "chio-receipts.jsonl"
    bad_path.mkdir()  # making it a dir guarantees open() raises
    with pytest.raises(OSError):
        append_jsonl(bad_path, {"x": 1})


def test_record_to_unwritable_path_swallows_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ReceiptBuffer.record` must NOT raise when the JSONL writer fails.

    Hermes treats any exception from a hook (which calls `record`) as a
    fatal session error; suppression here prevents disk pressure from
    killing the worker.
    """
    import chio_hermes.receipts as _receipts

    bad_path = tmp_path / "is_dir.jsonl"
    bad_path.mkdir()
    monkeypatch.setattr(_receipts, "_resolve_log_path", lambda: bad_path)

    buf = ReceiptBuffer()
    buf.record({"tool_name": "chio_file_read"})  # must not raise


# ---------------------------------------------------------------------------
# Concurrency: torn-line safety
# ---------------------------------------------------------------------------


def test_record_writes_under_lock_no_torn_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N parallel `record` calls must produce N intact JSON lines."""
    import chio_hermes.receipts as _receipts

    log = tmp_path / "chio-receipts.jsonl"
    monkeypatch.setattr(_receipts, "_resolve_log_path", lambda: log)

    buf = ReceiptBuffer()
    n = 64

    def worker(i: int) -> None:
        buf.record({"i": i, "filler": "x" * 256})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == n
    for line in lines:
        # Each line must parse independently as canonical JSON.
        json.loads(line)


def test_resolve_log_path_returns_path() -> None:
    """Smoke check that the resolver returns a Path object."""
    p = _resolve_log_path()
    assert isinstance(p, Path)
