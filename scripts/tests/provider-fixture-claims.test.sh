#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

python3 - "$REPO_ROOT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
fixture_roots = [
    root / "crates/protocol/chio-provider-conformance/fixtures/gemini",
    root / "crates/protocol/chio-provider-conformance/fixtures/mistral",
    root / "crates/protocol/chio-provider-conformance/fixtures/groq",
    root / "crates/protocol/chio-provider-conformance/fixtures/ollama",
    root / "crates/protocol/chio-provider-conformance/fixtures/cohere",
]


def response_tool_call_count(payload: dict[str, Any]) -> int:
    if isinstance(payload.get("choices"), list):
        count = 0
        for choice in payload["choices"]:
            message = choice.get("message") if isinstance(choice, dict) else None
            if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
                count += len(message["tool_calls"])
        return count
    message = payload.get("message")
    if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
        return len(message["tool_calls"])
    if isinstance(payload.get("candidates"), list):
        count = 0
        for candidate in payload["candidates"]:
            content = candidate.get("content") if isinstance(candidate, dict) else None
            parts = content.get("parts") if isinstance(content, dict) else None
            if isinstance(parts, list):
                count += sum(1 for part in parts if isinstance(part, dict) and "functionCall" in part)
        return count
    return 0


def response_choice_count(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    return len(value) if isinstance(value, list) else 0


def has_stream_arg_fragments(records: list[dict[str, Any]]) -> bool:
    for record in records:
        if record.get("direction") != "upstream_event":
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        stage = str(payload.get("stage", ""))
        capture_mode = str(payload.get("capture_mode", ""))
        event = str(payload.get("event", ""))
        if "stream" in stage or "stream" in capture_mode or "delta" in event:
            return True
    return False


failures: list[str] = []
for fixture_root in fixture_roots:
    for path in sorted(fixture_root.glob("*.ndjson")):
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        fixture_id = path.stem
        response_payloads = [
            record.get("payload", {})
            for record in records
            if record.get("direction") == "upstream_response" and isinstance(record.get("payload"), dict)
        ]
        verdict_count = sum(1 for record in records if record.get("direction") == "kernel_verdict")

        if "parallel" in fixture_id:
            max_calls = max((response_tool_call_count(payload) for payload in response_payloads), default=0)
            if max_calls < 2 or verdict_count < 2:
                failures.append(f"{path.relative_to(root)} claims parallel but has {max_calls} response calls and {verdict_count} verdicts")
        if "multi_choice" in fixture_id:
            max_choices = max((response_choice_count(payload, "choices") for payload in response_payloads), default=0)
            if max_choices < 2:
                failures.append(f"{path.relative_to(root)} claims multi_choice but has {max_choices} choices")
        if "multi_candidate" in fixture_id:
            max_candidates = max((response_choice_count(payload, "candidates") for payload in response_payloads), default=0)
            if max_candidates < 2:
                failures.append(f"{path.relative_to(root)} claims multi_candidate but has {max_candidates} candidates")
        if "stream" in fixture_id and not any(record.get("direction") == "upstream_event" for record in records):
            failures.append(f"{path.relative_to(root)} claims stream but has no upstream_event records")
        if "split_args" in fixture_id and not has_stream_arg_fragments(records):
            failures.append(f"{path.relative_to(root)} claims split_args but has no stream argument fragments")

if failures:
    raise SystemExit("\n".join(failures))
PY

echo "provider-fixture-claims.test.sh: provider fixture claim names match captured shapes"
