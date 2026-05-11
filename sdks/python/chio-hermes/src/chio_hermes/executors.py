"""Async I/O executors for the chio-hermes tool surface.

`chio_code_agent` ships default executors for `read_file` / `write_file`
only; the other ten tool methods accept an `executor` kwarg with no
default and silently no-op without one. This module supplies the
missing executors so the plugin can apply real filesystem / subprocess
/ git effects after the sidecar emits an allow verdict.

All paths are resolved relative to the explicit `cwd` kwarg and
rejected if they escape via symlink or `..`. Subprocess calls always
pass an argv list (NEVER `shell=True`), capture stdout + stderr,
honour `CHIO_SHELL_TIMEOUT` (default 60 s), and run inside
`asyncio.to_thread` so the Hermes event loop stays free.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_SHELL_TIMEOUT = 60


def workspace_root() -> Path:
    """Return the workspace root for ad-hoc CLI use.

    Hermes-side callers thread `cwd=` through the handler factories;
    this fallback is for unit tests of executors invoked without `cwd`.
    """
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
    """Resolve `path` and confirm it lives inside `root`.

    Falls back to a lexical resolve for non-existent targets so writes
    that create new files are still gated.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        # Target may not exist yet (e.g. chio_file_write); lexical
        # resolve still handles `..`.
        resolved = Path(os.path.normpath(str(candidate)))
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError(
            f"path {path!r} resolves outside the workspace root"
        ) from exc
    return resolved


def _run_subprocess(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdin: str | None = None,
) -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603 - argv is a list, never shell=True
        argv,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        input=stdin,
        check=False,
    )
    return {
        "argv": list(argv),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _resolve_cwd(cwd: Path | None) -> Path:
    if cwd is not None:
        return Path(cwd).resolve()
    return workspace_root()


async def edit_file_executor(
    *, path: str, patch: str, cwd: Path | None = None
) -> dict[str, Any]:
    """Apply `patch` to `path` via `patch -p0` reading the diff on stdin.

    Using `patch(1)` avoids an extra `unidiff` dependency.
    """
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
    """Search files by glob via `Path.rglob(query)` under `path`.

    Returns paths relative to the workspace root for stable test output.
    """
    root = _resolve_cwd(cwd)
    target = _resolve_within(path, root)
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"search root {path!r} is not a directory")
    matches: list[str] = []
    for hit in target.rglob(query):
        try:
            matches.append(str(hit.relative_to(root)))
        except ValueError:
            # rglob can return paths under symlinked subtrees; keep the
            # absolute path rather than dropping silently.
            matches.append(str(hit))
    matches.sort()
    return {"path": str(target), "query": query, "matches": matches}


async def shell_run_executor(
    *, command: str, cwd: Path | None = None
) -> dict[str, Any]:
    """Run `command` after tokenising via `shlex.split` (NEVER shell=True)."""
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
    root = _resolve_cwd(cwd)
    return await asyncio.to_thread(
        _run_subprocess,
        ["git", *args],
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
    if not message:
        raise ValueError("git_commit requires a non-empty message")
    return await _git("commit", "-m", message, cwd=cwd)


async def git_run_executor(
    *, command: str, cwd: Path | None = None
) -> dict[str, Any]:
    """Run an arbitrary `git ...` command after `shlex.split`."""
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
    "workspace_root",
]
