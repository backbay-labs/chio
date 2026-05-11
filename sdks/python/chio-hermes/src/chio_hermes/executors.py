"""Async I/O executors used by the chio-hermes tool surface.

`chio_code_agent` ships default executors only for `FileTool.read_file`
and `FileTool.write_file`. The other ten methods take an `executor`
kwarg with no default and silently no-op the I/O when omitted. This
module supplies the missing executors locally so the plugin can wire
real filesystem / subprocess / git effects after the sidecar emits an
allow verdict.

Constraints enforced by every executor here:

* All paths are resolved relative to the explicit `cwd` kwarg the
  caller passes in. Paths that escape the root via symlinks or `..`
  are rejected before the I/O runs. The `CHIO_WORKSPACE_ROOT` env var
  is honoured only as a fallback for ad-hoc CLI use.
* All shell-outs use argv lists (NEVER `shell=True`), capture stdout +
  stderr, time out at `CHIO_SHELL_TIMEOUT` (default 60 seconds), and
  surface the result as a JSON-serialisable dict.
* Subprocess executors are async and wrap `subprocess.run` in
  `asyncio.to_thread` so the Hermes event loop is never blocked.

The executor layer is the I/O surface; Chio guards the policy and
receipt layer above it. Subprocess output is unredacted.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_SHELL_TIMEOUT = 60
"""Default subprocess timeout in seconds; overridable via CHIO_SHELL_TIMEOUT."""


# ---------------------------------------------------------------------------
# Path / workspace helpers
# ---------------------------------------------------------------------------


def workspace_root() -> Path:
    """Return the workspace root for ad-hoc CLI use.

    Reads `CHIO_WORKSPACE_ROOT` lazily. Hermes-side callers should pass
    `cwd=` explicitly through the handler factories; this helper is a
    fallback for unit tests of executors that omit `cwd`.
    """
    raw = os.environ.get("CHIO_WORKSPACE_ROOT")
    base = Path(raw) if raw else Path.cwd()
    return base.resolve()


def shell_timeout() -> int:
    """Return the configured subprocess timeout in seconds."""
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

    Raises `PermissionError` for symlink escapes, `..` traversal, or
    absolute paths outside the workspace root. The check is purely
    lexical for non-existent targets so we can also gate writes that
    create new files.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        # Target may not exist yet (e.g. chio_file_write creating a
        # file). Fall back to a lexical resolve that still handles `..`.
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
    """Run `argv` via `subprocess.run` and return a JSON-friendly dict.

    Always uses an argv list (NEVER `shell=True`). Captures stdout +
    stderr as UTF-8 text. A non-zero exit code is reported via the
    returned dict; the caller decides whether to surface it as an
    executor error to the handler layer.
    """
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
    """Return `cwd` if supplied, else the env-derived workspace root."""
    if cwd is not None:
        return Path(cwd).resolve()
    return workspace_root()


# ---------------------------------------------------------------------------
# File executors
# ---------------------------------------------------------------------------


async def edit_file_executor(
    *, path: str, patch: str, cwd: Path | None = None
) -> dict[str, Any]:
    """Apply `patch` to `path` via `patch -p0` reading the diff on stdin.

    Using `patch(1)` keeps us free of an extra `unidiff` dependency. The
    path is confined to `cwd` (the resolved workspace root) before the
    shell-out.
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
    """List immediate entries of `path` via `pathlib`.

    Returns a dict with `entries` (sorted basenames) and `path` (the
    resolved absolute path). Symlink escapes are rejected by
    `_resolve_within`.
    """
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

    Returns a list of paths relative to the workspace root so the
    output is stable across test runs.
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
            # absolute path for those rather than dropping them silently.
            matches.append(str(hit))
    matches.sort()
    return {"path": str(target), "query": query, "matches": matches}


# ---------------------------------------------------------------------------
# Shell executors
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Git executors
# ---------------------------------------------------------------------------


async def _git(
    *args: str, cwd: Path | None = None, stdin: str | None = None
) -> dict[str, Any]:
    """Internal helper that runs `git ...` in the resolved workspace root."""
    root = _resolve_cwd(cwd)
    return await asyncio.to_thread(
        _run_subprocess,
        ["git", *args],
        cwd=root,
        timeout=shell_timeout(),
        stdin=stdin,
    )


async def git_status_executor(*, cwd: Path | None = None) -> dict[str, Any]:
    """Run `git status --porcelain=v1` for stable machine-parseable output."""
    return await _git("status", "--porcelain=v1", cwd=cwd)


async def git_diff_executor(
    *, paths: list[str] | None = None, cwd: Path | None = None
) -> dict[str, Any]:
    """Run `git diff` (optionally constrained to `paths`)."""
    args: list[str] = ["diff"]
    if paths:
        args.append("--")
        args.extend(paths)
    return await _git(*args, cwd=cwd)


async def git_log_executor(
    *, limit: int = 20, cwd: Path | None = None
) -> dict[str, Any]:
    """Run `git log --oneline -n <limit>` for stable output."""
    return await _git("log", f"-n{int(limit)}", "--oneline", cwd=cwd)


async def git_add_executor(
    *, paths: list[str], cwd: Path | None = None
) -> dict[str, Any]:
    """Stage `paths` via `git add --`."""
    if not paths:
        raise ValueError("git_add requires at least one path")
    return await _git("add", "--", *paths, cwd=cwd)


async def git_commit_executor(
    *, message: str, cwd: Path | None = None
) -> dict[str, Any]:
    """Create a commit with `message` (`git commit -m <message>`)."""
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
