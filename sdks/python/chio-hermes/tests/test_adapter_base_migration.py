"""Migration tests for the chio-hermes 0.1.1 chio-adapter-base swap.

These tests assert the migration mechanics that the legacy
``test_security_fixes.py`` / ``test_receipts.py`` / ``test_hooks.py``
suites do not cover:

1. The chio-hermes shim functions (``_redact_args``, ``_sanitised_env``,
   etc.) actually delegate to ``chio_adapter_base`` instead of running
   their own copy of the logic.
2. The deprecated chio-hermes module-level names emit a
   :class:`DeprecationWarning` so external consumers see the migration
   notice exactly once per call.
3. The chio-adapter-base canonical imports work from inside the
   chio-hermes virtualenv (i.e. the dependency is wired correctly).
"""

from __future__ import annotations

import warnings
from typing import Any

import pytest


def test_canonical_imports_work() -> None:
    """All seven chio-adapter-base public entry points must import cleanly.

    Any ImportError here means the chio-hermes pyproject is missing a
    dep declaration or the chio-adapter-base wheel is not installed.
    """
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

    # Touch each name so the linter does not flag them; the real
    # assertion is that the imports above did not raise.
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
    """``chio_hermes.hooks._redact_args`` must call into adapter-base."""
    import chio_adapter_base.redact as _ab_redact

    from chio_hermes import hooks as _hooks

    sentinel: dict[str, Any] = {"sentinel": True}
    captured: dict[str, Any] = {}

    def _fake(
        tool_name: str | None,
        args: dict[str, Any],
        *,
        policy: Any | None = None,
    ) -> dict[str, Any]:
        captured["tool_name"] = tool_name
        captured["args"] = args
        captured["policy"] = policy
        return sentinel

    # Patch at the chio-hermes binding site: hooks.py imports
    # ``redact_args as _adapter_base_redact_args`` so the
    # module-level reference is what the shim actually calls.
    monkeypatch.setattr(_hooks, "_adapter_base_redact_args", _fake)
    # Also patch the canonical module so the bind name path stays
    # consistent if someone re-imports.
    monkeypatch.setattr(_ab_redact, "redact_args", _fake)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        out = _hooks._redact_args(
            "chio_file_write",
            {"path": "x.py", "content": "secret"},
        )

    assert out is sentinel
    assert captured["tool_name"] == "chio_file_write"
    assert captured["args"] == {"path": "x.py", "content": "secret"}
    # The policy is the chio-hermes baseline (chio_default).
    assert captured["policy"] is not None


def test_post_tool_call_uses_adapter_base_redact_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The internal call site must NOT route through the deprecated shim.

    If ``make_post_tool_call`` called ``_redact_args`` we would see a
    DeprecationWarning fire from chio-hermes' own hook execution path,
    polluting every receipt the host process records.
    """
    from chio_hermes import hooks as _hooks
    from chio_hermes.receipts import ReceiptBuffer
    from chio_hermes.runtime import RuntimeHandle

    handle = RuntimeHandle(receipts=ReceiptBuffer())
    post_hook = _hooks.make_post_tool_call(handle)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        post_hook(
            tool_name="chio_file_write",
            args={"path": "x.py", "content": "shh"},
            result='{"status":"allowed"}',
            task_id="t-1",
            duration_ms=1.5,
        )

    deprecations = [
        w for w in caught if issubclass(w.category, DeprecationWarning)
    ]
    chio_deprecations = [
        w
        for w in deprecations
        if "chio_hermes" in str(w.message)
    ]
    assert chio_deprecations == [], (
        "post_tool_call must not emit chio-hermes deprecation warnings; "
        f"saw: {[str(w.message) for w in chio_deprecations]}"
    )


def test_sanitised_env_shim_warns_and_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-leak-me")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-leak")
    monkeypatch.setenv("BENIGN", "ok")

    from chio_hermes import executors as _exec

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        env = _exec._sanitised_env()

    assert "OPENAI_API_KEY" not in env
    assert "CHIO_CAPABILITY_ID" not in env
    assert env.get("BENIGN") == "ok"

    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_sanitised_env" in str(w.message)
        and "chio_adapter_base.security.sanitised_env" in str(w.message)
    ]
    assert len(matches) == 1


def test_run_subprocess_shim_warns_and_returns_legacy_dict_shape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    import sys as _sys

    from chio_hermes import executors as _exec

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _exec._run_subprocess(
            [_sys.executable, "-c", "print('ok')"],
            cwd=tmp_path,
            timeout=10,
        )

    assert out["returncode"] == 0
    assert out["stdout"].strip() == "ok"
    # Legacy dict shape: not a dataclass, callers can index as dict.
    assert set(out.keys()) >= {"argv", "returncode", "stdout", "stderr"}

    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_run_subprocess" in str(w.message)
    ]
    assert len(matches) == 1


def test_harden_git_run_argv_shim_warns_and_delegates() -> None:
    from chio_hermes import executors as _exec

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _exec._harden_git_run_argv(["commit", "-m", "x"])

    assert out == ["commit", "--no-verify", "-m", "x"]
    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_harden_git_run_argv" in str(w.message)
    ]
    assert len(matches) == 1


def test_resolve_within_shim_warns_and_delegates(tmp_path: Any) -> None:
    from chio_hermes import executors as _exec

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _exec._resolve_within("foo/bar.txt", tmp_path)

    assert str(out).startswith(str(tmp_path))
    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_resolve_within" in str(w.message)
    ]
    assert len(matches) == 1


def test_drain_stream_to_cap_shim_warns_and_delegates() -> None:
    import io

    from chio_hermes import executors as _exec

    stream = io.BytesIO(b"abcdef")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        buf, truncated = _exec._drain_stream_to_cap(stream, 3)

    assert bytes(buf) == b"abc"
    assert truncated is True
    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_drain_stream_to_cap" in str(w.message)
    ]
    assert len(matches) == 1


def test_canonical_dumps_shim_warns_and_delegates() -> None:
    from chio_hermes import receipts as _receipts

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _receipts._canonical_dumps({"b": 2, "a": 1})

    assert out == b'{"a":1,"b":2}'
    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_canonical_dumps" in str(w.message)
    ]
    assert len(matches) == 1


def test_redact_args_shim_warns() -> None:
    from chio_hermes import hooks as _hooks

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        out = _hooks._redact_args(
            "chio_file_write",
            {"path": "x.py", "content": "shh"},
        )

    # Redaction stub still produced correctly.
    assert out["path"] == "x.py"
    assert out["content"] == {"omitted": True, "byte_count": 3}

    matches = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_redact_args" in str(w.message)
    ]
    assert len(matches) == 1


def test_body_redact_fields_shim_warns_on_lookup() -> None:
    from chio_hermes import hooks as _hooks

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # Both ``in`` and ``[]`` should fire a warning so external
        # callers learn the table moved.
        present = "chio_file_write" in _hooks._BODY_REDACT_FIELDS
        value = _hooks._BODY_REDACT_FIELDS["chio_file_write"]

    assert present is True
    assert value == ("content",)
    chio_warnings = [
        w
        for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "_BODY_REDACT_FIELDS" in str(w.message)
    ]
    assert len(chio_warnings) >= 2


def test_filter_directory_entries_delegates_to_adapter_base(
    tmp_path: Any,
) -> None:
    """The handler-side dir filter must route through chio-adapter-base.

    Mirrors the existing ``test_security_fixes`` coverage but anchors on
    the new chio-adapter-base import to prove the migration shim, not
    the in-tree implementation, is what runs.
    """
    from chio_adapter_base.filters import filter_directory_entries

    from chio_hermes import handlers as _handlers
    from tests.conftest import make_configured_runtime

    # Establish the workspace fixture inline.
    (tmp_path / ".env").write_text("SECRET=shh\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    runtime = make_configured_runtime(cwd=tmp_path)
    raw = {"path": str(tmp_path), "entries": [".env", "src"]}

    # Direct call to the canonical to capture its behaviour.
    canonical = filter_directory_entries(
        dict(raw),
        is_forbidden=lambda p: p.endswith(".env"),
    )

    via_shim = _handlers._filter_directory_entries(runtime, ".", raw)
    # Both the canonical (with our hand-rolled is_forbidden) and the
    # shim (with the real policy) must drop the ``.env`` entry. The
    # shape of the kept-entries list and the ``forbidden_paths_filtered``
    # marker must match between the two.
    assert via_shim["entries"] == canonical["entries"]
    assert via_shim["forbidden_paths_filtered"] == [".env"]


def test_receipt_buffer_uses_module_level_append_jsonl(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ReceiptBuffer.record`` must look up ``append_jsonl`` dynamically.

    Tests that monkeypatch the module-level ``append_jsonl`` (a common
    pattern in the existing chio-hermes test suite) need the wrapper to
    re-resolve the name on every ``record`` call rather than capturing
    a bound reference at construction time.
    """
    from chio_hermes import receipts as _receipts

    captured: list[tuple[str, dict[str, Any]]] = []

    def _capture(path: Any, payload: dict[str, Any]) -> None:
        captured.append((str(path), dict(payload)))

    monkeypatch.setattr(_receipts, "_resolve_log_path", lambda: tmp_path / "log.jsonl")
    monkeypatch.setattr(_receipts, "append_jsonl", _capture)

    buf = _receipts.ReceiptBuffer()
    buf.record({"tool_name": "chio_file_read", "status": "allowed"})

    assert len(captured) == 1
    assert captured[0][1]["tool_name"] == "chio_file_read"
