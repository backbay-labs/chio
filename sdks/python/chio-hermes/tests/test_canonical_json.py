"""Byte-canonical conformance check for the JSONL receipt log.

Writes one receipt via `append_jsonl`, reads it back, and compares
byte-for-byte against a frozen golden so the on-disk audit trail is
deterministic across Python versions, dict insertion orders, and
locales. The fixture deliberately uses non-sorted insertion order and
a nested dict; canonical JSON must sort both.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from chio_hermes.receipts import _canonical_dumps, append_jsonl

# Frozen golden. If this changes, the receipt format has changed and
# the JSONL log is no longer cross-version-stable; bump the receipt
# format version explicitly rather than papering over the diff here.
GOLDEN_LINE = (
    '{"capability_id":"cap-aaaa11112222","decision":'
    '{"guard":"ForbiddenPathGuard","reason":"path .env is forbidden",'
    '"verdict":"deny"},"id":"rcpt-fixed-0001","tool_name":"chio_file_write",'
    '"tool_server":"fs"}'
)


def test_record_byte_identity_against_golden(tmp_path: Path) -> None:
    log = tmp_path / "chio-receipts.jsonl"
    payload = {
        "tool_server": "fs",
        "tool_name": "chio_file_write",
        "id": "rcpt-fixed-0001",
        "capability_id": "cap-aaaa11112222",
        "decision": {
            "verdict": "deny",
            "reason": "path .env is forbidden",
            "guard": "ForbiddenPathGuard",
        },
    }
    append_jsonl(log, payload)

    line = log.read_text(encoding="utf-8").rstrip("\n")
    assert line == GOLDEN_LINE, (
        "JSONL receipt is no longer byte-canonical.\n"
        f"  expected: {GOLDEN_LINE!r}\n"
        f"  got:      {line!r}\n"
        "If the format intentionally changed, update GOLDEN_LINE and bump "
        "the receipt format version."
    )


def test_canonical_dumps_helper_matches_byte_form() -> None:
    out = _canonical_dumps({"b": 2, "a": 1})
    assert out == b'{"a":1,"b":2}'


def test_post_hook_record_round_trip_byte_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end byte identity for a record built like a post-hook."""
    monkeypatch.setattr(time, "time", lambda: 1700000000)
    log = tmp_path / "chio-receipts.jsonl"
    record: dict[str, Any] = {
        "tool_name": "chio_file_read",
        "args": {"path": "README.md"},
        "task_id": "task-stable-1",
        "duration_ms": 12.5,
        "recorded_at": time.time(),
        "result": '{"status":"allowed"}',
    }
    append_jsonl(log, record)
    line = log.read_text(encoding="utf-8").rstrip("\n")
    expected = (
        '{"args":{"path":"README.md"},'
        '"duration_ms":12.5,'
        '"recorded_at":1700000000,'
        '"result":"{\\"status\\":\\"allowed\\"}",'
        '"task_id":"task-stable-1",'
        '"tool_name":"chio_file_read"}'
    )
    assert line == expected
    assert json.loads(line) == record
