from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict

from chio_hermes import handlers as _handlers
from chio_hermes import hooks as _hooks
from chio_hermes import runtime as _runtime
from chio_hermes.commands import make_slash_handler
from chio_hermes.handlers import make_handler
from chio_hermes.manifest import TOOL_TABLE
from chio_hermes.receipts import ReceiptBuffer
from tests.conftest import make_configured_runtime


def _allow_all_policy(_t: str, _s: dict, _c: dict) -> MockVerdict:
    return MockVerdict.allow_verdict()


def test_runtime_fails_closed_when_policy_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CHIO_POLICY_FILE opt-in must not fall back to DEFAULT_POLICY.
    missing = tmp_path / "does-not-exist.yaml"
    monkeypatch.setenv("CHIO_POLICY_FILE", str(missing))
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-test-12345678")
    monkeypatch.chdir(tmp_path)

    handle = _runtime.build_runtime_handle()
    assert handle.is_configured() is False
    assert handle.init_error is not None
    assert "policy_load_failed" in handle.init_error


def test_runtime_uses_default_policy_when_env_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHIO_POLICY_FILE", raising=False)
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-test-12345678")
    monkeypatch.chdir(tmp_path)

    handle = _runtime.build_runtime_handle()
    assert handle.policy is not None
    assert handle.init_error is None


def test_filter_diff_output_drops_forbidden_hunks(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    diff_text = (
        "diff --git a/.env b/.env\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "+SECRET=topsecret\n"
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "+x = 2\n"
    )
    raw = {"stdout": diff_text, "returncode": 0}
    filtered = _handlers._filter_diff_output(runtime, raw)
    assert "SECRET=topsecret" not in filtered["stdout"]
    assert "x = 2" in filtered["stdout"]
    assert ".env" in filtered["forbidden_paths_filtered"]


def test_filter_diff_output_no_op_on_clean_diff(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "stdout": (
            "diff --git a/src/main.py b/src/main.py\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "+x = 1\n"
        ),
        "returncode": 0,
    }
    out = _handlers._filter_diff_output(runtime, raw)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


@pytest.mark.asyncio
async def test_chio_shell_run_rejects_dotdot_token(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chio_hermes import executors as _exec

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(_exec, "shell_run_executor", _ok)

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_allow_all_policy), cwd=tmp_workspace
    )
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_shell_run"])

    payload = json.loads(
        await handler({"command": "cat ../etc/passwd"}, task_id="t-escape")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "chio_path_escape"


@pytest.mark.asyncio
async def test_chio_git_add_rejects_forbidden_expansion(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pathspec expanding to .env is denied even when the literal
    # pathspec passes policy.check_write.
    runtime = make_configured_runtime(cwd=tmp_workspace)

    async def _fake_expand(_handle: Any, _paths: list[str]) -> list[str]:
        return [".env"]

    monkeypatch.setattr(_handlers, "_expand_git_pathspecs", _fake_expand)

    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_git_add"])

    payload = json.loads(
        await handler({"paths": ["src/**"]}, task_id="t-add-forbid")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "forbidden_path"


def test_chio_git_add_string_path_is_not_split_into_characters() -> None:
    assert _handlers._coerce_git_add_paths(".env") == [".env"]


def test_chio_git_add_rejects_non_string_paths() -> None:
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    with pytest.raises(ChioCodeAgentDeniedError):
        _handlers._coerce_git_add_paths([{"path": ".env"}])


def test_filter_directory_entries_drops_dotenv(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "path": str(tmp_workspace),
        "entries": [".env", "README.md", "src"],
    }
    filtered = _handlers._filter_directory_entries(runtime, ".", raw)
    assert ".env" not in filtered["entries"]
    assert "README.md" in filtered["entries"]
    assert filtered["forbidden_paths_filtered"] == [".env"]


@pytest.mark.parametrize(
    "command",
    [
        "-C /tmp status",
        "--git-dir=/tmp/.git status",
        "--work-tree=/tmp status",
    ],
)
def test_reject_git_run_flag_escape(command: str) -> None:
    from chio_code_agent.errors import ChioCodeAgentDeniedError

    with pytest.raises(ChioCodeAgentDeniedError) as excinfo:
        _handlers._reject_git_run_flag_escape(command)
    assert excinfo.value.guard == "chio_path_escape"


def test_reject_git_run_flag_escape_allows_safe_git() -> None:
    _handlers._reject_git_run_flag_escape("status --porcelain")


def test_truncate_receipt_result_truncates_file_read() -> None:
    big = '{"status":"allowed","result":"' + ("A" * 1024) + '"}'
    payload, truncated = _hooks._truncate_receipt_result("chio_file_read", big)
    assert truncated is True
    assert isinstance(payload, str)
    assert len(payload.encode("utf-8")) <= _hooks.RECEIPT_RESULT_MAX_BYTES


def test_truncate_receipt_result_passthrough_for_small_payload() -> None:
    payload, truncated = _hooks._truncate_receipt_result(
        "chio_file_read", '{"status":"allowed"}'
    )
    assert truncated is False
    assert payload == '{"status":"allowed"}'


def test_truncate_receipt_result_passthrough_for_chio_file_write() -> None:
    big = '{"status":"allowed","result":"' + ("A" * 1024) + '"}'
    payload, truncated = _hooks._truncate_receipt_result("chio_file_write", big)
    assert truncated is False
    assert payload == big


@pytest.mark.asyncio
async def test_chio_file_search_rejects_dotdot_query(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chio_hermes import executors as _exec

    async def _ok(**_kw: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr(_exec, "search_files_executor", _ok)

    runtime = make_configured_runtime(
        chio_client=MockChioClient(policy=_allow_all_policy), cwd=tmp_workspace
    )
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_file_search"])

    payload = json.loads(
        await handler({"query": "../*"}, task_id="t-query-escape")
    )
    assert payload["error"] == "denied"
    assert payload["guard"] == "chio_path_escape"


@pytest.mark.asyncio
async def test_chio_git_run_routes_to_hitl_when_check_shell_requires_approval(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Custom policy: check_shell returning True (approval required)
    # now holds the call in the sidecar's HITL channel rather than
    # denying outright.
    import copy

    from chio_code_agent.policy import DEFAULT_POLICY, AllowedTool

    custom_policy = copy.copy(DEFAULT_POLICY)
    custom_policy.allowed_tools = set(DEFAULT_POLICY.allowed_tools) | {
        AllowedTool(server="git", tool="run")
    }

    runtime = make_configured_runtime(cwd=tmp_workspace, policy=custom_policy)

    monkeypatch.setattr(runtime.policy, "check_shell", lambda _cmd: True)
    monkeypatch.setattr(runtime.policy, "check_git", lambda _cmd: None)

    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_git_run"])

    payload = json.loads(
        await handler({"command": "status"}, task_id="t-git-run-approve")
    )
    assert payload["error"] == "chio_requires_approval"
    assert payload["status"] == "requires_approval"
    assert payload["approval_id"].startswith("mock-ap-")
    assert payload["tool_server"] == "git"
    assert payload["command"] == "status"


@pytest.mark.asyncio
async def test_slash_chio_handles_unclosed_quote(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    handle_slash = make_slash_handler(runtime)
    out = await handle_slash('"unclosed')
    assert out is not None
    assert "could not parse" in out


def test_receipt_buffer_recent_zero_returns_empty() -> None:
    buf = ReceiptBuffer()
    for i in range(5):
        buf._buffer.append({"i": i})  # type: ignore[attr-defined]
    assert buf.recent(0) == []
    assert buf.recent(-1) == []
    assert len(buf.recent(2)) == 2


@pytest.mark.asyncio
async def test_executor_error_recovers_receipt_id_from_context(
    tmp_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Generic executor exception still surfaces the receipt id from
    # the most recent allow verdict via the client wrapper.
    captured: dict[str, Any] = {}

    class _ClientCapture(MockChioClient):
        async def evaluate_tool_call(self, **kw: Any) -> Any:
            receipt = await super().evaluate_tool_call(**kw)
            captured["receipt_id"] = receipt.id
            return receipt

    client = _ClientCapture(policy=_allow_all_policy)
    _runtime._install_receipt_id_capture(client)

    runtime = make_configured_runtime(chio_client=client, cwd=tmp_workspace)

    async def _boom(**_kw: Any) -> Any:
        raise RuntimeError("disk full")

    from chio_hermes import executors as _exec

    monkeypatch.setattr(_exec, "edit_file_executor", _boom)
    by_name = {entry.name: entry for entry in TOOL_TABLE}
    handler = make_handler(runtime, by_name["chio_file_edit"])

    payload = json.loads(
        await handler(
            {"path": "src/new.py", "patch": "--- a\n+++ b\n"},
            task_id="t-recover-rid",
        )
    )
    assert payload["error"] == "chio_executor_error"
    assert payload["receipt_id"] == captured["receipt_id"]


def test_capability_cache_file_is_mode_0600(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Cache holds bearer credentials; must chmod 0600.
    import os
    import stat

    from chio_hermes import cli as _cli

    home = tmp_path / "hermes-home"
    monkeypatch.setattr(_cli, "_hermes_home", lambda: home)
    monkeypatch.setenv("HERMES_PROFILE", "default")

    _cli._save_cache([{"capability_id": "cap-x", "revoked": False}])

    cache = _cli._cache_path()
    assert cache.exists()
    mode = stat.S_IMODE(os.stat(cache).st_mode)
    assert mode == 0o600, f"expected 0600, got 0o{mode:o}"


def test_capability_cache_save_is_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Tempfile + replace guards against a torn write under concurrent
    # `hermes chio issue` (race F15).
    from chio_hermes import cli as _cli

    home = tmp_path / "hermes-home"
    monkeypatch.setattr(_cli, "_hermes_home", lambda: home)
    monkeypatch.setenv("HERMES_PROFILE", "default")

    _cli._save_cache([{"capability_id": "cap-1"}])
    _cli._save_cache([{"capability_id": "cap-1"}, {"capability_id": "cap-2"}])

    text = _cli._cache_path().read_text(encoding="utf-8")
    parsed = json.loads(text)
    assert [entry["capability_id"] for entry in parsed] == ["cap-1", "cap-2"]


def test_run_subprocess_strips_credential_env_vars(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Child must not inherit CHIO_* / _API_KEY / _TOKEN env vars.
    import sys

    from chio_hermes import executors as _exec

    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-secret-do-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-openai")
    monkeypatch.setenv("MY_CUSTOM_TOKEN", "secret-token-value")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    out = _exec._run_subprocess(
        [
            sys.executable,
            "-c",
            "import json,os,sys; sys.stdout.write(json.dumps(dict(os.environ)))",
        ],
        cwd=tmp_path,
        timeout=10,
    )
    assert out["returncode"] == 0
    child_env = json.loads(out["stdout"])
    assert "CHIO_CAPABILITY_ID" not in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "MY_CUSTOM_TOKEN" not in child_env
    assert child_env.get("BENIGN_VAR") == "ok"


@pytest.mark.asyncio
async def test_git_commit_executor_passes_no_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --no-verify guards against repo-local hook scripts escalating
    # to RCE on the host.
    import subprocess as _subprocess

    from chio_hermes import executors as _exec

    captured: dict[str, Any] = {}

    class _FakeProc:
        returncode = 0

        def __init__(self) -> None:
            self.stdout: Any = None
            self.stderr: Any = None
            self.stdin: Any = None

        def wait(self, timeout: int | None = None) -> int:  # noqa: ARG002
            return 0

        def kill(self) -> None:  # pragma: no cover
            pass

    def fake_popen(argv: list[str], **kw: Any) -> _FakeProc:
        captured["argv"] = list(argv)
        captured["kwargs"] = dict(kw)
        return _FakeProc()

    monkeypatch.setattr(_subprocess, "Popen", fake_popen)

    out = await _exec.git_commit_executor(message="test", cwd=tmp_path)
    assert out["returncode"] == 0
    assert "--no-verify" in captured["argv"]
    assert "commit" in captured["argv"]


def test_redact_args_omits_chio_file_write_content() -> None:
    redacted = _hooks._redact_args(
        "chio_file_write",
        {"path": "src/main.py", "content": "SECRET=topsecret\n"},
    )
    assert redacted["path"] == "src/main.py"
    assert redacted["content"] == {"omitted": True, "byte_count": 17}


def test_redact_args_omits_chio_file_edit_patch() -> None:
    patch_body = "--- a/src/main.py\n+++ b/src/main.py\n+x = 1\n"
    redacted = _hooks._redact_args(
        "chio_file_edit", {"path": "src/main.py", "patch": patch_body}
    )
    assert redacted["path"] == "src/main.py"
    assert redacted["patch"]["omitted"] is True
    assert redacted["patch"]["byte_count"] == len(patch_body.encode("utf-8"))


def test_redact_args_passthrough_for_chio_shell_run() -> None:
    # chio_shell_run.command is the auditable bit; pass through.
    redacted = _hooks._redact_args(
        "chio_shell_run", {"command": "ls -la /tmp"}
    )
    assert redacted == {"command": "ls -la /tmp"}


def test_filter_search_matches_drops_forbidden(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "path": str(tmp_workspace),
        "query": "*",
        "matches": [".env", "src/main.py", "README.md"],
    }
    filtered = _handlers._filter_matches(runtime, raw)
    assert ".env" not in filtered["matches"]
    assert "src/main.py" in filtered["matches"]
    assert filtered["forbidden_paths_filtered"] == [".env"]


def test_filter_search_matches_no_op_when_clean(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {"matches": ["src/main.py", "README.md"]}
    out = _handlers._filter_matches(runtime, raw)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


def test_filter_status_output_drops_forbidden_rows(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "stdout": " M src/main.py\n?? .env\n M README.md\n",
        "returncode": 0,
    }
    filtered = _handlers._filter_status_output(runtime, raw)
    assert ".env" not in filtered["stdout"]
    assert "src/main.py" in filtered["stdout"]
    assert "README.md" in filtered["stdout"]
    assert ".env" in filtered["forbidden_paths_filtered"]


def test_filter_status_output_handles_renames(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {
        "stdout": "R  README.md -> .env\n M src/main.py\n",
        "returncode": 0,
    }
    filtered = _handlers._filter_status_output(runtime, raw)
    assert ".env" not in filtered["stdout"]
    assert "src/main.py" in filtered["stdout"]


def test_filter_status_output_no_op_when_clean(tmp_workspace: Path) -> None:
    runtime = make_configured_runtime(cwd=tmp_workspace)
    raw = {"stdout": " M src/main.py\n", "returncode": 0}
    out = _handlers._filter_status_output(runtime, raw)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


def test_run_subprocess_truncates_runaway_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Streaming child is truncated rather than buffered to OOM.
    import sys

    from chio_hermes import executors as _exec

    monkeypatch.setenv("CHIO_SUBPROCESS_MAX_BYTES", "4096")

    out = _exec._run_subprocess(
        [
            sys.executable,
            "-c",
            "import sys\nfor _ in range(2000):\n    sys.stdout.write('x' * 100)",
        ],
        cwd=tmp_path,
        timeout=15,
    )
    assert out.get("output_truncated") is True
    assert len(out["stdout"].encode("utf-8")) <= 4096 + 1


def test_run_subprocess_strips_git_config_and_hook_overrides(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GIT_CONFIG_* / GIT_HOOKS_PATH / GIT_DIR / GIT_WORK_TREE /
    # GIT_INDEX_FILE / GIT_ALTERNATE_OBJECT_DIRECTORIES /
    # GIT_OBJECT_DIRECTORY in the parent env can defeat workspace
    # anchoring or `--no-verify`. They must not reach the child.
    import sys

    from chio_hermes import executors as _exec

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/tmp/evil-hooks")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/tmp/evil.gitconfig")
    monkeypatch.setenv("GIT_HOOKS_PATH", "/tmp/evil-hooks")
    monkeypatch.setenv("GIT_DIR", "/tmp/other/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/tmp/other")
    monkeypatch.setenv("GIT_INDEX_FILE", "/tmp/alt-index")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/tmp/alt-objs")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/tmp/alt-objs")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    out = _exec._run_subprocess(
        [
            sys.executable,
            "-c",
            "import json,os,sys; sys.stdout.write(json.dumps(dict(os.environ)))",
        ],
        cwd=tmp_path,
        timeout=10,
    )
    assert out["returncode"] == 0
    child_env = json.loads(out["stdout"])
    for leaked in (
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_SYSTEM",
        "GIT_HOOKS_PATH",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_OBJECT_DIRECTORY",
    ):
        assert leaked not in child_env, f"{leaked} leaked into child env"
    assert child_env.get("BENIGN_VAR") == "ok"


def test_harden_git_run_argv_injects_no_verify_for_commit() -> None:
    from chio_hermes import executors as _exec

    out = _exec._harden_git_run_argv(["commit", "-m", "x"])
    assert out == ["commit", "--no-verify", "-m", "x"]


def test_harden_git_run_argv_skips_when_no_verify_present() -> None:
    from chio_hermes import executors as _exec

    out = _exec._harden_git_run_argv(["commit", "--no-verify", "-m", "x"])
    assert out == ["commit", "--no-verify", "-m", "x"]


def test_harden_git_run_argv_rejects_explicit_verify() -> None:
    from chio_hermes import executors as _exec

    with pytest.raises(PermissionError):
        _exec._harden_git_run_argv(["commit", "--verify", "-m", "x"])


def test_harden_git_run_argv_passes_through_non_commit_subcommands() -> None:
    from chio_hermes import executors as _exec

    assert _exec._harden_git_run_argv(["status", "--porcelain"]) == [
        "status",
        "--porcelain",
    ]
    assert _exec._harden_git_run_argv(["log", "-n5"]) == ["log", "-n5"]


def test_harden_git_run_argv_skips_leading_global_flags() -> None:
    # `git -c foo=bar commit -m x` -- leading -c is a global option,
    # not the subcommand. The implementation walks past leading flags
    # until it finds the first non-flag token.
    from chio_hermes import executors as _exec

    out = _exec._harden_git_run_argv(["-c", "user.name=x", "commit", "-m", "y"])
    assert out == ["-c", "user.name=x", "commit", "--no-verify", "-m", "y"]


def test_on_session_start_flushes_pending_into_recorded_buffer() -> None:
    # F14: per-turn on_session_start must flush pending into recorded
    # rather than silently drop them.
    from chio_hermes.receipts import ReceiptBuffer
    from chio_hermes.runtime import RuntimeHandle

    receipts = ReceiptBuffer()
    receipts.push("task-A", {"tool_name": "chio_file_read", "args": {}})
    receipts.push("task-B", {"tool_name": "chio_file_write", "args": {}})

    handle = RuntimeHandle(receipts=receipts)
    on_start = _hooks.make_on_session_start(handle)
    on_start(session_id="sess-1")

    assert receipts.pending_total() == 0
    recent = receipts.recent(10)
    assert len(recent) == 2
    assert all(entry.get("session_start_flush") for entry in recent)
