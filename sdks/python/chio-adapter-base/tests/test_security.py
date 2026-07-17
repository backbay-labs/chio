"""Behavioural tests for :mod:`chio_adapter_base.security`.

These assertions mirror
``sdks/python/chio-hermes/tests/test_security_fixes.py`` and cover the
same threats the chio-hermes implementation is hardened against.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from chio_adapter_base.security import (
    DEFAULT_SHELL_TIMEOUT,
    DEFAULT_SUBPROCESS_MAX_BYTES,
    BoundedSubprocess,
    BoundedSubprocessResult,
    ChioPathEscapeError,
    harden_git_argv,
    reject_shell_argv_escape,
    resolve_within,
    sanitised_env,
)


def test_sanitised_env_drops_chio_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-secret")
    monkeypatch.setenv("HERMES_HOME", "/tmp/x")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    env = sanitised_env()
    assert "CHIO_CAPABILITY_ID" not in env
    assert "HERMES_HOME" not in env
    assert env.get("BENIGN_VAR") == "ok"


def test_sanitised_env_drops_credential_suffixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MY_API_KEY", "k")
    monkeypatch.setenv("USER_TOKEN", "t")
    monkeypatch.setenv("CUSTOM_SECRET", "s")
    monkeypatch.setenv("DB_PASSWORD", "p")
    monkeypatch.setenv("KEY_PRIVATE_KEY", "pk")
    monkeypatch.setenv("CONFIG_CREDENTIALS", "c")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    env = sanitised_env()
    for leaked in (
        "MY_API_KEY",
        "USER_TOKEN",
        "CUSTOM_SECRET",
        "DB_PASSWORD",
        "KEY_PRIVATE_KEY",
        "CONFIG_CREDENTIALS",
    ):
        assert leaked not in env, f"{leaked} leaked"
    assert env.get("BENIGN_VAR") == "ok"


def test_sanitised_env_drops_exact_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgres://...")
    monkeypatch.setenv("DOCKER_PASSWORD", "p")
    monkeypatch.setenv("GIT_DIR", "/tmp/.git")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    env = sanitised_env()
    assert "DATABASE_URL" not in env
    assert "DOCKER_PASSWORD" not in env
    assert "GIT_DIR" not in env
    assert env.get("BENIGN_VAR") == "ok"


def test_sanitised_env_drops_exact_names_case_insensitively() -> None:
    env = sanitised_env(
        base={
            "database_url": "postgres://...",
            "git_dir": "/tmp/.git",
            "BENIGN_VAR": "ok",
        }
    )
    assert "database_url" not in env
    assert "git_dir" not in env
    assert env.get("BENIGN_VAR") == "ok"


def test_sanitised_env_accepts_explicit_base() -> None:
    env = sanitised_env(base={"OPENAI_API_KEY": "k", "FOO": "bar"})
    assert "OPENAI_API_KEY" not in env
    assert env.get("FOO") == "bar"


def test_harden_git_argv_injects_no_verify_for_commit() -> None:
    out = harden_git_argv(["commit", "-m", "x"])
    assert out == ["commit", "--no-verify", "-m", "x"]


def test_harden_git_argv_skips_when_no_verify_present() -> None:
    out = harden_git_argv(["commit", "--no-verify", "-m", "x"])
    assert out == ["commit", "--no-verify", "-m", "x"]


def test_harden_git_argv_rejects_explicit_verify() -> None:
    with pytest.raises(PermissionError):
        harden_git_argv(["commit", "--verify", "-m", "x"])


def test_harden_git_argv_passes_through_non_commit_subcommands() -> None:
    assert harden_git_argv(["status", "--porcelain"]) == [
        "status",
        "--porcelain",
    ]
    assert harden_git_argv(["log", "-n5"]) == ["log", "-n5"]
    assert harden_git_argv(["add", "commit"]) == ["add", "commit"]


def test_harden_git_argv_skips_leading_global_flags() -> None:
    out = harden_git_argv(["-c", "user.name=x", "commit", "-m", "y"])
    assert out == ["-c", "user.name=x", "commit", "--no-verify", "-m", "y"]


def test_harden_git_argv_skips_value_taking_c_global() -> None:
    out = harden_git_argv(["-C", "repo", "commit", "-m", "y"])
    assert out == ["-C", "repo", "commit", "--no-verify", "-m", "y"]
    with pytest.raises(PermissionError):
        harden_git_argv(["-C", "repo", "commit", "--verify"])

    out = harden_git_argv(["git", "--git-dir", ".git", "commit", "-m", "y"])
    assert out == ["git", "--git-dir", ".git", "commit", "--no-verify", "-m", "y"]
    with pytest.raises(PermissionError):
        harden_git_argv(["git", "--git-dir", ".git", "commit", "--verify"])


def test_harden_git_argv_skips_git_global_values_named_commit() -> None:
    assert harden_git_argv(["-C", "commit", "status"]) == [
        "-C",
        "commit",
        "status",
    ]
    assert harden_git_argv(["--git-dir", "commit", "status"]) == [
        "--git-dir",
        "commit",
        "status",
    ]


def test_harden_git_argv_allows_git_binary_prefix() -> None:
    out = harden_git_argv(["git", "-c", "user.name=x", "commit", "-m", "y"])
    assert out == ["git", "-c", "user.name=x", "commit", "--no-verify", "-m", "y"]


def test_harden_git_argv_allows_windows_git_binary_prefix() -> None:
    out = harden_git_argv(["git.exe", "-C", "repo", "commit", "-m", "y"])
    assert out == ["git.exe", "-C", "repo", "commit", "--no-verify", "-m", "y"]
    with pytest.raises(PermissionError):
        harden_git_argv(
            [r"C:\Program Files\Git\bin\git.exe", "commit", "--verify"]
        )


def test_harden_git_argv_does_not_mutate_input() -> None:
    src = ["commit", "-m", "x"]
    out = harden_git_argv(src)
    assert src == ["commit", "-m", "x"]
    assert out is not src


def test_reject_shell_argv_escape_rejects_dotdot(tmp_path: Path) -> None:
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape("cat ../etc/passwd", root=tmp_path)
    assert excinfo.value.reason == "dotdot_segment"
    assert ".." in excinfo.value.token


def test_reject_shell_argv_escape_rejects_outside_workspace(
    tmp_path: Path,
) -> None:
    other = tmp_path.parent / "other-tree"
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape(f"cat {other}/secret.txt", root=tmp_path)
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_rejects_unresolvable_absolute_path(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "outside" / "secret.txt"
    with patch.object(Path, "resolve", side_effect=[tmp_path, OSError("missing")]):
        with pytest.raises(ChioPathEscapeError) as excinfo:
            reject_shell_argv_escape(f"cat {outside}", root=tmp_path)
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_rejects_windows_absolute_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape("cat 'C:\\outside\\secret.txt'", root=tmp_path)
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_rejects_unquoted_windows_absolute_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape("cat C:\\outside\\secret.txt", root=tmp_path)
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_rejects_embedded_windows_absolute_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape(
            "tool --config='C:\\outside\\secret.txt'",
            root=tmp_path,
        )
    assert excinfo.value.reason == "outside_workspace"

    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape(
            'TOOL_CONFIG="C:\\outside\\secret.txt" tool',
            root=tmp_path,
        )
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_allows_windows_absolute_inside_workspace() -> None:
    reject_shell_argv_escape(
        r"type C:\repo\README.md",
        root=r"C:\repo",
    )
    reject_shell_argv_escape(
        r"type 'C:\repo\docs\guide.md'",
        root=r"C:\repo",
    )
    reject_shell_argv_escape(
        r"tool --config='C:\repo\settings.toml'",
        root=r"C:\repo",
    )


def test_reject_shell_argv_escape_allows_quoted_windows_workspace_with_spaces() -> None:
    reject_shell_argv_escape(
        r'type "C:\repo dir\README.md"',
        root=r"C:\repo dir",
    )
    reject_shell_argv_escape(
        r"tool --config='C:\repo dir\settings.toml'",
        root=r"C:\repo dir",
    )
    reject_shell_argv_escape(
        r'TOOL_CONFIG="C:\repo dir\settings.toml" tool',
        root=r"C:\repo dir",
    )


def test_reject_shell_argv_escape_allows_colon_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    service_cwd = tmp_path / "service"
    workspace.mkdir()
    service_cwd.mkdir()
    monkeypatch.chdir(service_cwd)
    reject_shell_argv_escape("echo a:b C:tmp", root=workspace)


def test_reject_shell_argv_escape_allows_url_arguments(tmp_path: Path) -> None:
    reject_shell_argv_escape("curl https://example.com", root=tmp_path)
    reject_shell_argv_escape(
        "git clone https://github.com/org/repo.git",
        root=tmp_path,
    )
    reject_shell_argv_escape(
        "python -m pip install git+https://github.com/org/repo.git",
        root=tmp_path,
    )


def test_reject_shell_argv_escape_allows_single_letter_ssh_remotes(
    tmp_path: Path,
) -> None:
    reject_shell_argv_escape("scp a:/var/log/app.log .", root=tmp_path)
    reject_shell_argv_escape("rsync user@x:/src ./dst", root=tmp_path)
    reject_shell_argv_escape("sftp z:/srv/export", root=tmp_path)


def test_reject_shell_argv_escape_still_rejects_drive_like_non_remote(
    tmp_path: Path,
) -> None:
    with pytest.raises(ChioPathEscapeError) as excinfo:
        reject_shell_argv_escape("cat a:/var/log/app.log", root=tmp_path)
    assert excinfo.value.reason == "outside_workspace"


def test_reject_shell_argv_escape_allows_workspace_path(tmp_path: Path) -> None:
    inside = tmp_path / "src" / "main.py"
    reject_shell_argv_escape(f"cat {inside}", root=tmp_path)


def test_reject_shell_argv_escape_silent_on_malformed_quoting(
    tmp_path: Path,
) -> None:
    # Should NOT raise; the executor surfaces the syntax error.
    reject_shell_argv_escape('cat "unclosed', root=tmp_path)


def test_reject_shell_argv_escape_no_root_skips_absolute_check() -> None:
    # ``..`` still rejected even with no root.
    with pytest.raises(ChioPathEscapeError):
        reject_shell_argv_escape("cat ../x", root=None)
    # Absolute path is allowed when root is None.
    reject_shell_argv_escape("cat /etc/passwd", root=None)


def test_resolve_within_accepts_inside_path(tmp_path: Path) -> None:
    inside = tmp_path / "src" / "main.py"
    inside.parent.mkdir()
    inside.write_text("x", encoding="utf-8")
    resolved = resolve_within("src/main.py", tmp_path)
    assert resolved == inside.resolve()


def test_resolve_within_rejects_dotdot_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(PermissionError):
        resolve_within("../escape.txt", workspace)


def test_resolve_within_handles_nonexistent_target(tmp_path: Path) -> None:
    # File does not yet exist (chio_file_write target). Lexical fallback
    # still validates the path stays inside the workspace.
    resolved = resolve_within("not-yet-created.txt", tmp_path)
    assert str(resolved).startswith(str(tmp_path))


def test_resolve_within_rejects_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = workspace / "link.txt"
    link.symlink_to(outside)
    with pytest.raises(PermissionError):
        resolve_within("link.txt", workspace)


def test_bounded_subprocess_runs_simple_command(tmp_path: Path) -> None:
    sub = BoundedSubprocess()
    result = sub.run([sys.executable, "-c", "print('hi')"], cwd=tmp_path)
    assert isinstance(result, BoundedSubprocessResult)
    assert result.returncode == 0
    assert result.stdout.strip() == "hi"
    assert result.output_truncated is False


def test_bounded_subprocess_truncates_runaway_output(tmp_path: Path) -> None:
    sub = BoundedSubprocess(max_bytes=4096)
    result = sub.run(
        [
            sys.executable,
            "-c",
            "import sys\nfor _ in range(2000):\n    sys.stdout.write('x' * 100)",
        ],
        cwd=tmp_path,
    )
    assert result.output_truncated is True
    # Allow up to one extra chunk byte for the truncation accounting.
    assert len(result.stdout.encode("utf-8")) <= 4096 + 1


def test_bounded_subprocess_strips_credential_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-secret-do-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-openai")
    monkeypatch.setenv("MY_CUSTOM_TOKEN", "secret-token-value")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    sub = BoundedSubprocess()
    result = sub.run(
        [
            sys.executable,
            "-c",
            "import json,os,sys; sys.stdout.write(json.dumps(dict(os.environ)))",
        ],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    child_env = json.loads(result.stdout)
    assert "CHIO_CAPABILITY_ID" not in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "MY_CUSTOM_TOKEN" not in child_env
    assert child_env.get("BENIGN_VAR") == "ok"


def test_bounded_subprocess_strips_git_config_overrides(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_HOOKS_PATH", "/tmp/evil-hooks")
    monkeypatch.setenv("GIT_DIR", "/tmp/other/.git")
    monkeypatch.setenv("BENIGN_VAR", "ok")

    sub = BoundedSubprocess()
    result = sub.run(
        [
            sys.executable,
            "-c",
            "import json,os,sys; sys.stdout.write(json.dumps(dict(os.environ)))",
        ],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    child_env = json.loads(result.stdout)
    for leaked in ("GIT_CONFIG_COUNT", "GIT_HOOKS_PATH", "GIT_DIR"):
        assert leaked not in child_env, f"{leaked} leaked into child env"
    assert child_env.get("BENIGN_VAR") == "ok"


def test_bounded_subprocess_uses_env_factory(tmp_path: Path) -> None:
    sub = BoundedSubprocess(env_factory=lambda: {"FOO": "bar"})
    result = sub.run(
        [
            sys.executable,
            "-c",
            "import json,os,sys; sys.stdout.write(json.dumps(dict(os.environ)))",
        ],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    child_env = json.loads(result.stdout)
    assert child_env.get("FOO") == "bar"


def test_bounded_subprocess_timeout_raises(tmp_path: Path) -> None:
    sub = BoundedSubprocess(timeout_seconds=1)
    with pytest.raises(subprocess.TimeoutExpired):
        sub.run(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
        )


def test_bounded_subprocess_passes_stdin(tmp_path: Path) -> None:
    sub = BoundedSubprocess()
    result = sub.run(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
        cwd=tmp_path,
        stdin="hello-stdin",
    )
    assert result.returncode == 0
    assert result.stdout == "hello-stdin"


@pytest.mark.asyncio
async def test_bounded_subprocess_arun(tmp_path: Path) -> None:
    sub = BoundedSubprocess()
    result = await sub.arun(
        [sys.executable, "-c", "print('async-hi')"], cwd=tmp_path
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "async-hi"


def test_default_constants_match_chio_hermes() -> None:
    assert DEFAULT_SHELL_TIMEOUT == 60
    assert DEFAULT_SUBPROCESS_MAX_BYTES == 1 << 20
