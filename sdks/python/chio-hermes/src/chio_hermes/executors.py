"""Async I/O executors for the chio-hermes tool surface.

`chio_code_agent` ships default executors for `read_file` / `write_file`
only; the other ten tool methods accept an `executor` kwarg with no
default and silently no-op without one.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_SHELL_TIMEOUT = 60
DEFAULT_SUBPROCESS_MAX_BYTES = 1 << 20  # 1 MiB

# Credential-carrying env vars stripped from child processes. See
# HERMES.md "Security model" for the contract.
_ENV_DENY_PREFIXES: tuple[str, ...] = (
    "CHIO_",
    "HERMES_",
    "AWS_",
    "GOOGLE_",
    "GCP_",
    "AZURE_",
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GH_",
    "GITHUB_",
    "GIT_AUTH_",
    "VAULT_",
    "DATABRICKS_",
    "HF_",
    "HUGGINGFACE_",
)
_ENV_DENY_SUFFIXES: tuple[str, ...] = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_PRIVATE_KEY",
    "_CREDENTIALS",
    "_CREDS",
)
_ENV_DENY_EXACT: frozenset[str] = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "DOCKER_PASSWORD",
        "SLACK_TOKEN",
        "DATABASE_URL",
    }
)


def _is_denied_env(name: str) -> bool:
    if name in _ENV_DENY_EXACT:
        return True
    upper = name.upper()
    if any(upper.startswith(prefix) for prefix in _ENV_DENY_PREFIXES):
        return True
    if any(upper.endswith(suffix) for suffix in _ENV_DENY_SUFFIXES):
        return True
    return False


def _sanitised_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not _is_denied_env(k)}


def subprocess_max_bytes() -> int:
    raw = os.environ.get("CHIO_SUBPROCESS_MAX_BYTES")
    if not raw:
        return DEFAULT_SUBPROCESS_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_SUBPROCESS_MAX_BYTES
    return value if value > 0 else DEFAULT_SUBPROCESS_MAX_BYTES


def workspace_root() -> Path:
    # Fallback for executors invoked without `cwd`; Hermes-side callers
    # thread `cwd=` through the handler factories.
    raw = os.environ.get("CHIO_WORKSPACE_ROOT")
    base = Path(raw) if raw else Path.cwd()
    return base.resolve()


def shell_timeout() -> int:
    raw = os.environ.get("CHIO_SHELL_TIMEOUT")
    if not raw:
        return DEFAULT_SHELL_TIMEOUT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_SHELL_TIMEOUT
    return value if value > 0 else DEFAULT_SHELL_TIMEOUT


def _resolve_within(path: str, root: Path) -> Path:
    """Resolve `path` and confirm it lives inside `root`."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        # Target may not exist yet (chio_file_write); lexical resolve
        # still handles `..`.
        resolved = Path(os.path.normpath(str(candidate)))
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError(
            f"path {path!r} resolves outside the workspace root"
        ) from exc
    return resolved


def _drain_stream_to_cap(
    stream: Any, cap: int
) -> tuple[bytearray, bool]:
    # Continue draining past the cap so the producer does not block on
    # a full pipe (which would cause the surrounding wait() to time out
    # even when the cap was meant to be the bound).
    buf = bytearray()
    truncated = False
    if stream is None:
        return buf, False
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        if len(buf) >= cap:
            truncated = True
            continue
        room = cap - len(buf)
        if len(chunk) <= room:
            buf.extend(chunk)
        else:
            buf.extend(chunk[:room])
            truncated = True
    return buf, truncated


def _run_subprocess(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdin: str | None = None,
) -> dict[str, Any]:
    # `subprocess.run(..., capture_output=True)` buffers all output in
    # memory until exit; a tool that streams large output (yes, big
    # `git diff`) can OOM Hermes before the timeout fires. Spawn via
    # Popen and drain each pipe in a thread with a per-stream cap.
    import threading

    env = _sanitised_env()
    cap = subprocess_max_bytes()
    proc = subprocess.Popen(  # noqa: S603 - argv is a list, never shell=True
        argv,
        cwd=str(cwd),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    drained: dict[str, tuple[bytearray, bool]] = {
        "stdout": (bytearray(), False),
        "stderr": (bytearray(), False),
    }

    def _reader(name: str, stream: Any) -> None:
        drained[name] = _drain_stream_to_cap(stream, cap)

    stdout_thread = threading.Thread(
        target=_reader, args=("stdout", proc.stdout), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_reader, args=("stderr", proc.stderr), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        if stdin is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin.encode("utf-8"))
            finally:
                proc.stdin.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait()
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            if stream is not None:
                try:
                    stream.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass

    if timed_out:
        # Mirror subprocess.run so the caller sees TimeoutExpired rather
        # than a silent returncode=-9.
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    stdout_buf, stdout_truncated = drained["stdout"]
    stderr_buf, stderr_truncated = drained["stderr"]
    out: dict[str, Any] = {
        "argv": list(argv),
        "returncode": proc.returncode,
        "stdout": stdout_buf.decode("utf-8", errors="replace"),
        "stderr": stderr_buf.decode("utf-8", errors="replace"),
    }
    if stdout_truncated or stderr_truncated:
        out["output_truncated"] = True
    return out


def _resolve_cwd(cwd: Path | None) -> Path:
    if cwd is not None:
        return Path(cwd).resolve()
    return workspace_root()


async def edit_file_executor(
    *, path: str, patch: str, cwd: Path | None = None
) -> dict[str, Any]:
    # Use `patch(1)` to avoid an extra `unidiff` dependency.
    root = _resolve_cwd(cwd)
    target = _resolve_within(path, root)
    result = await asyncio.to_thread(
        _run_subprocess,
        ["patch", "-p0", str(target)],
        cwd=root,
        timeout=shell_timeout(),
        stdin=patch,
    )
    if result["returncode"] != 0:
        raise RuntimeError(
            f"patch failed for {path!r}: {result['stderr'].strip() or result['stdout'].strip()}"
        )
    return {"path": str(target), **result}


async def list_directory_executor(
    *, path: str, cwd: Path | None = None
) -> dict[str, Any]:
    root = _resolve_cwd(cwd)
    target = _resolve_within(path, root)
    if not target.exists():
        raise FileNotFoundError(f"directory {path!r} does not exist")
    if not target.is_dir():
        raise NotADirectoryError(f"path {path!r} is not a directory")
    entries = sorted(p.name for p in target.iterdir())
    return {"path": str(target), "entries": entries}


async def search_files_executor(
    *, query: str, path: str = ".", cwd: Path | None = None
) -> dict[str, Any]:
    root = _resolve_cwd(cwd)
    target = _resolve_within(path, root)
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"search root {path!r} is not a directory")
    matches: list[str] = []
    for hit in target.rglob(query):
        try:
            matches.append(str(hit.relative_to(root)))
        except ValueError:
            # rglob can return paths under symlinked subtrees; keep
            # absolute rather than dropping silently.
            matches.append(str(hit))
    matches.sort()
    return {"path": str(target), "query": query, "matches": matches}


async def shell_run_executor(
    *, command: str, cwd: Path | None = None
) -> dict[str, Any]:
    root = _resolve_cwd(cwd)
    argv = shlex.split(command)
    if not argv:
        raise ValueError("command must contain at least one token")
    return await asyncio.to_thread(
        _run_subprocess, argv, cwd=root, timeout=shell_timeout()
    )


async def _git(
    *args: str, cwd: Path | None = None, stdin: str | None = None
) -> dict[str, Any]:
    # Anchor git at `cwd` (`-C <root>` plus `--git-dir`/`--work-tree`
    # when present) so a workspace inside a larger worktree does not
    # silently pick up the parent's git config / .gitignore.
    root = _resolve_cwd(cwd)
    git_argv: list[str] = ["git", "-C", str(root)]
    git_dir = root / ".git"
    if git_dir.is_dir():
        git_argv.extend(["--git-dir", str(git_dir), "--work-tree", str(root)])
    git_argv.extend(args)
    return await asyncio.to_thread(
        _run_subprocess,
        git_argv,
        cwd=root,
        timeout=shell_timeout(),
        stdin=stdin,
    )


async def git_status_executor(*, cwd: Path | None = None) -> dict[str, Any]:
    return await _git("status", "--porcelain=v1", cwd=cwd)


async def git_diff_executor(
    *, paths: list[str] | None = None, cwd: Path | None = None
) -> dict[str, Any]:
    args: list[str] = ["diff"]
    if paths:
        args.append("--")
        args.extend(paths)
    return await _git(*args, cwd=cwd)


async def git_log_executor(
    *, limit: int = 20, cwd: Path | None = None
) -> dict[str, Any]:
    return await _git("log", f"-n{int(limit)}", "--oneline", cwd=cwd)


async def git_add_executor(
    *, paths: list[str], cwd: Path | None = None
) -> dict[str, Any]:
    if not paths:
        raise ValueError("git_add requires at least one path")
    return await _git("add", "--", *paths, cwd=cwd)


async def git_commit_executor(
    *, message: str, cwd: Path | None = None
) -> dict[str, Any]:
    # `--no-verify` is mandatory: pre-commit / commit-msg /
    # prepare-commit-msg hooks execute repo-local scripts in the
    # commit's working tree, escalating "model can call git_commit"
    # to arbitrary code execution. Users who want hooks can dispatch
    # them via `chio_shell_run` (gated by the shell deny list).
    if not message:
        raise ValueError("git_commit requires a non-empty message")
    return await _git("commit", "--no-verify", "-m", message, cwd=cwd)


async def git_run_executor(
    *, command: str, cwd: Path | None = None
) -> dict[str, Any]:
    argv = shlex.split(command)
    if not argv:
        raise ValueError("git_run requires a non-empty command")
    if argv[0] == "git":
        argv = argv[1:]
    if not argv:
        raise ValueError("git_run command must include a git subcommand")
    return await _git(*argv, cwd=cwd)


__all__ = [
    "DEFAULT_SHELL_TIMEOUT",
    "DEFAULT_SUBPROCESS_MAX_BYTES",
    "edit_file_executor",
    "git_add_executor",
    "git_commit_executor",
    "git_diff_executor",
    "git_log_executor",
    "git_run_executor",
    "git_status_executor",
    "list_directory_executor",
    "search_files_executor",
    "shell_run_executor",
    "shell_timeout",
    "subprocess_max_bytes",
    "workspace_root",
]
