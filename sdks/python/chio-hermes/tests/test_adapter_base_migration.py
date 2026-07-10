"""Tests that chio-hermes delegates shared primitives to chio-adapter-base."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


def test_canonical_imports_work() -> None:
    """All chio-adapter-base public entry points import cleanly."""
    from chio_adapter_base.filters import (
        filter_diff_output,
        filter_directory_entries,
        filter_status_output,
        forbidden_path_filter,
    )
    from chio_adapter_base.receipts import (
        ReceiptBuffer,
        append_jsonl,
        canonical_dumps,
    )
    from chio_adapter_base.redact import (
        RedactionPolicy,
        redact_args,
    )
    from chio_adapter_base.security import (
        BoundedSubprocess,
        ChioPathEscapeError,
        harden_git_argv,
        reject_shell_argv_escape,
        resolve_within,
        sanitised_env,
    )

    for symbol in (
        filter_diff_output,
        filter_directory_entries,
        filter_status_output,
        forbidden_path_filter,
        ReceiptBuffer,
        append_jsonl,
        canonical_dumps,
        RedactionPolicy,
        redact_args,
        BoundedSubprocess,
        ChioPathEscapeError,
        harden_git_argv,
        reject_shell_argv_escape,
        resolve_within,
        sanitised_env,
    ):
        assert callable(symbol) or hasattr(symbol, "__name__")


def test_redact_args_delegates_to_adapter_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import chio_hermes.hooks as hooks

    sentinel: dict[str, Any] = {"sentinel": True}
    captured: dict[str, Any] = {}

    def fake_redact_args(
        tool_name: str | None,
        args: dict[str, Any],
        *,
        policy: Any | None = None,
    ) -> dict[str, Any]:
        captured["tool_name"] = tool_name
        captured["args"] = args
        captured["policy"] = policy
        return sentinel

    monkeypatch.setattr(hooks, "_adapter_base_redact_args", fake_redact_args)

    out = hooks._redact_args("chio_file_write", {"content": "secret"})

    assert out is sentinel
    assert captured == {
        "tool_name": "chio_file_write",
        "args": {"content": "secret"},
        "policy": hooks._DEFAULT_REDACTION_POLICY,
    }


def test_executor_helpers_delegate_to_adapter_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import chio_hermes.executors as executors

    calls: dict[str, Any] = {}

    def fake_resolve(path: str, root: Path) -> Path:
        calls["resolve"] = (path, root)
        return root / path

    def fake_sanitised_env() -> dict[str, str]:
        calls["sanitised_env"] = True
        return {"PATH": "/usr/bin"}

    monkeypatch.setattr(executors, "_adapter_base_resolve_within", fake_resolve)
    monkeypatch.setattr(executors, "_adapter_base_sanitised_env", fake_sanitised_env)

    root = Path("/tmp/chio")

    assert executors._resolve_within("file.txt", root) == root / "file.txt"
    assert executors._sanitised_env() == {"PATH": "/usr/bin"}
    assert calls == {
        "resolve": ("file.txt", root),
        "sanitised_env": True,
    }


def test_receipt_canonical_dumps_delegates_to_adapter_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import chio_hermes.receipts as receipts

    sentinel = b'{"ok":true}'
    captured: dict[str, Any] = {}

    def fake_canonical_dumps(record: dict[str, Any]) -> bytes:
        captured["record"] = record
        return sentinel

    monkeypatch.setattr(receipts, "_adapter_base_canonical_dumps", fake_canonical_dumps)

    assert receipts._canonical_dumps({"ok": True}) is sentinel
    assert captured == {"record": {"ok": True}}
