"""Behavioural tests for :mod:`chio_adapter_base.receipts`."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from chio_adapter_base.receipts import (
    DEFAULT_RECEIPT_BUFFER_MAX,
    ReceiptBuffer,
    append_jsonl,
    canonical_dumps,
)


def test_canonical_dumps_is_sorted_and_compact() -> None:
    out = canonical_dumps({"b": 2, "a": 1})
    # Sorted keys, no whitespace.
    assert out == b'{"a":1,"b":2}'


def test_canonical_dumps_is_ascii_safe() -> None:
    out = canonical_dumps({"k": "café"})
    assert b"\\u" in out
    # Round-trip preserves the original string.
    assert json.loads(out.decode("utf-8"))["k"] == "café"


def test_canonical_dumps_rejects_non_finite_float() -> None:
    with pytest.raises(ValueError):
        canonical_dumps({"cost": math.nan})


def test_append_jsonl_writes_canonical_line(tmp_path: Path) -> None:
    log = tmp_path / "logs" / "receipts.jsonl"
    append_jsonl(log, {"b": 2, "a": 1})
    append_jsonl(log, {"x": "y"})
    raw = log.read_bytes()
    lines = raw.splitlines()
    assert lines == [b'{"a":1,"b":2}', b'{"x":"y"}']


def test_receipt_buffer_fifo_per_task_id() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("A", {"i": 2})
    buf.push("B", {"i": 99})
    assert buf.pop_next("A") == {"i": 1}
    assert buf.pop_next("A") == {"i": 2}
    assert buf.pop_next("A") is None
    assert buf.pop_next("B") == {"i": 99}


def test_receipt_buffer_pop_none_task_id_uses_sentinel() -> None:
    buf = ReceiptBuffer()
    buf.push(None, {"i": 1})
    assert buf.pop_next(None) == {"i": 1}
    assert buf.pop_next(None) is None


def test_receipt_buffer_record_counts_denials() -> None:
    buf = ReceiptBuffer()
    buf.record({"status": "allowed"})
    buf.record({"status": "denied"})
    buf.record({"error": "denied"})
    assert buf.denial_count() == 2


def test_receipt_buffer_recent_zero_returns_empty() -> None:
    buf = ReceiptBuffer()
    for i in range(5):
        buf.record({"i": i})
    assert buf.recent(0) == []
    assert buf.recent(-1) == []
    assert len(buf.recent(2)) == 2


def test_receipt_buffer_recent_returns_tail() -> None:
    buf = ReceiptBuffer()
    for i in range(5):
        buf.record({"i": i})
    assert buf.recent(3) == [{"i": 2}, {"i": 3}, {"i": 4}]


def test_receipt_buffer_buffer_max_default() -> None:
    buf = ReceiptBuffer()
    # Insert one more than the max; oldest must drop.
    for i in range(DEFAULT_RECEIPT_BUFFER_MAX + 5):
        buf.record({"i": i})
    recent = buf.recent(DEFAULT_RECEIPT_BUFFER_MAX + 10)
    assert len(recent) == DEFAULT_RECEIPT_BUFFER_MAX
    assert recent[0] == {"i": 5}


def test_receipt_buffer_custom_buffer_max() -> None:
    buf = ReceiptBuffer(buffer_max=3)
    for i in range(5):
        buf.record({"i": i})
    assert buf.recent(10) == [{"i": 2}, {"i": 3}, {"i": 4}]


def test_receipt_buffer_clear_pending_all() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("B", {"i": 2})
    buf.clear_pending()
    assert buf.pending_total() == 0


def test_receipt_buffer_clear_pending_specific_task() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("B", {"i": 2})
    buf.clear_pending("A")
    assert buf.pop_next("A") is None
    assert buf.pop_next("B") == {"i": 2}


def test_receipt_buffer_drain_pending_all() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("B", {"i": 2})
    drained = buf.drain_pending()
    assert len(drained) == 2
    assert buf.pending_total() == 0


def test_receipt_buffer_drain_pending_per_task() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("A", {"i": 2})
    buf.push("B", {"i": 99})
    drained = buf.drain_pending("A")
    assert drained == [{"i": 1}, {"i": 2}]
    assert buf.pending_total() == 1
    assert buf.pop_next("B") == {"i": 99}


def test_receipt_buffer_writes_jsonl_when_factory_provided(
    tmp_path: Path,
) -> None:
    log = tmp_path / "logs" / "receipts.jsonl"
    buf = ReceiptBuffer(log_path_factory=lambda: log)
    buf.record({"status": "allowed", "tool": "x"})
    buf.record({"status": "denied", "tool": "y"})
    raw = log.read_bytes()
    lines = [json.loads(line) for line in raw.splitlines()]
    assert lines[0] == {"status": "allowed", "tool": "x"}
    assert lines[1] == {"status": "denied", "tool": "y"}


def test_receipt_buffer_record_swallows_jsonl_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Path under a regular file (cannot be a directory). mkdir(parents=True,
    # exist_ok=True) raises NotADirectoryError (subclass of OSError) which
    # the implementation must catch and log to stderr rather than crash.
    blocker = tmp_path / "blocker"
    blocker.write_text("file", encoding="utf-8")
    bad = blocker / "logs" / "receipts.jsonl"
    buf = ReceiptBuffer(log_path_factory=lambda: bad)
    # Must not raise.
    buf.record({"status": "allowed"})
    assert "receipt JSONL write failed" in caplog.text


def test_receipt_buffer_record_swallows_json_serialization_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    log = tmp_path / "receipts.jsonl"
    buf = ReceiptBuffer(log_path_factory=lambda: log)
    buf.record({"status": "allowed", "cost": math.inf})
    assert buf.recent(1)[0]["cost"] == math.inf
    assert not log.exists()
    assert "receipt JSONL write failed" in caplog.text


def test_receipt_buffer_record_swallows_json_type_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    log = tmp_path / "receipts.jsonl"
    buf = ReceiptBuffer(log_path_factory=lambda: log)
    buf.record({"status": "allowed", "raw": b"not-json"})
    assert buf.recent(1)[0]["raw"] == b"not-json"
    assert not log.exists()
    assert "receipt JSONL write failed" in caplog.text


def test_receipt_buffer_pending_total_aggregates() -> None:
    buf = ReceiptBuffer()
    buf.push("A", {"i": 1})
    buf.push("A", {"i": 2})
    buf.push("B", {"i": 3})
    assert buf.pending_total() == 3


def test_receipt_buffer_record_does_not_share_dict_with_caller() -> None:
    buf = ReceiptBuffer()
    payload: dict[str, object] = {"status": "allowed"}
    buf.record(payload)
    payload["status"] = "denied"
    # The recorded receipt must not see the post-record mutation.
    assert buf.recent(1)[0]["status"] == "allowed"
