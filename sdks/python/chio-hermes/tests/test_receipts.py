"""ReceiptBuffer + JSONL writer behaviour.

Three contracts:

1. FIFO order on `push` / `pop_next` for the same `task_id`.
2. Canonical JSON (sorted keys, no whitespace, ASCII-safe) on disk.
3. `record` swallows OSError so a transient disk problem cannot crash
   Hermes; `append_jsonl` itself raises so direct callers can decide.
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


def test_buffer_cap_uses_default() -> None:
    buf = ReceiptBuffer()
    for i in range(DEFAULT_RECEIPT_BUFFER_MAX + 5):
        buf._buffer.append({"i": i})  # type: ignore[attr-defined]
    assert len(buf._buffer) == DEFAULT_RECEIPT_BUFFER_MAX  # type: ignore[attr-defined]


def test_append_jsonl_propagates_oserror(tmp_path: Path) -> None:
    """Free function raises OSError so callers can decide."""
    bad_path = tmp_path / "chio-receipts.jsonl"
    bad_path.mkdir()  # making it a dir guarantees open() raises
    with pytest.raises(OSError):
        append_jsonl(bad_path, {"x": 1})


def test_record_to_unwritable_path_swallows_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ReceiptBuffer.record` must NOT raise when the JSONL writer fails.

    Hermes treats any exception from a hook (which calls `record`) as a
    fatal session error.
    """
    import chio_hermes.receipts as _receipts

    bad_path = tmp_path / "is_dir.jsonl"
    bad_path.mkdir()
    monkeypatch.setattr(_receipts, "_resolve_log_path", lambda: bad_path)

    buf = ReceiptBuffer()
    buf.record({"tool_name": "chio_file_read"})  # must not raise


def test_record_writes_under_lock_no_torn_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N parallel `record` calls produce N intact JSON lines."""
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
        json.loads(line)


def test_resolve_log_path_returns_path() -> None:
    p = _resolve_log_path()
    assert isinstance(p, Path)
