"""Async I/O executors for the chio-hermes tool surface.

`chio_code_agent` ships default executors for `read_file` / `write_file`
only; the other ten tool methods accept an `executor` kwarg with no
default and silently no-op without one.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from pathlib import Path
from typing import Any

from chio_adapter_base.security import (
    _ENV_DENY_EXACT as _ADAPTER_BASE_ENV_DENY_EXACT,
)
from chio_adapter_base.security import (
    _ENV_DENY_PREFIXES as _ADAPTER_BASE_ENV_DENY_PREFIXES,
)
from chio_adapter_base.security import (
    _ENV_DENY_SUFFIXES as _ADAPTER_BASE_ENV_DENY_SUFFIXES,
)

# The seven security primitives below are sourced from
# :mod:`chio_adapter_base.security`. The chio-hermes module-level names
# delegate to chio-adapter-base so this package has one security implementation.
from chio_adapter_base.security import (
    DEFAULT_SHELL_TIMEOUT as _ADAPTER_BASE_DEFAULT_SHELL_TIMEOUT,
)
from chio_adapter_base.security import (
    DEFAULT_SUBPROCESS_MAX_BYTES as _ADAPTER_BASE_DEFAULT_SUBPROCESS_MAX_BYTES,
)
from chio_adapter_base.security import BoundedSubprocess as _BoundedSubprocess
from chio_adapter_base.security import _is_denied_env as _adapter_base_is_denied_env
from chio_adapter_base.security import (
    harden_git_argv as _adapter_base_harden_git_argv,
)
from chio_adapter_base.security import resolve_within as _adapter_base_resolve_within
from chio_adapter_base.security import sanitised_env as _adapter_base_sanitised_env

# Re-exported constants stay byte-identical with the chio-adapter-base
# canonicals.
DEFAULT_SHELL_TIMEOUT = _ADAPTER_BASE_DEFAULT_SHELL_TIMEOUT
DEFAULT_SUBPROCESS_MAX_BYTES = _ADAPTER_BASE_DEFAULT_SUBPROCESS_MAX_BYTES
_ENV_DENY_PREFIXES: tuple[str, ...] = _ADAPTER_BASE_ENV_DENY_PREFIXES
_ENV_DENY_SUFFIXES: tuple[str, ...] = _ADAPTER_BASE_ENV_DENY_SUFFIXES
_ENV_DENY_EXACT: frozenset[str] = _ADAPTER_BASE_ENV_DENY_EXACT


def _is_denied_env(name: str) -> bool:
    """Delegates to ``chio_adapter_base.security._is_denied_env``."""
    return _adapter_base_is_denied_env(name)


def _sanitised_env() -> dict[str, str]:
    """Delegates to ``chio_adapter_base.security.sanitised_env``."""
    return _adapter_base_sanitised_env()


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
    """Delegates to ``chio_adapter_base.security.resolve_within``."""
    return _resolve_within_impl(path, root)


def _resolve_within_impl(path: str, root: Path) -> Path:
    """Delegates to ``chio_adapter_base.security.resolve_within``."""
    return _adapter_base_resolve_within(path, root)


def _drain_stream_to_cap(
    stream: Any, cap: int
) -> tuple[bytearray, bool]:
    """Delegates to ``chio_adapter_base.security._drain_stream_to_cap``."""
    from chio_adapter_base.security import _drain_stream_to_cap as _impl

    return _impl(stream, cap)


def _run_subprocess(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdin: str | None = None,
) -> dict[str, Any]:
    """Delegates to ``chio_adapter_base.security.BoundedSubprocess.run``.

    Returns the chio-hermes dict shape (``{"argv", "returncode",
    "stdout", "stderr", "output_truncated"?}``); the canonical
    :class:`BoundedSubprocessResult` dataclass exposes the same fields.
    """
    return _run_subprocess_impl(argv, cwd=cwd, timeout=timeout, stdin=stdin)


def _run_subprocess_impl(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdin: str | None = None,
) -> dict[str, Any]:
    """Internal: bounded subprocess run returning the dict shape.

    Wraps :class:`BoundedSubprocess` and adapts the
    :class:`BoundedSubprocessResult` dataclass back to the chio-hermes
    dict so the executor / handler code that calls into this module
    sees the dict keys (``argv`` / ``returncode`` / ``stdout`` /
    ``stderr`` / optional ``output_truncated``).
    """
    runner = _BoundedSubprocess(
        max_bytes=subprocess_max_bytes(),
        timeout_seconds=timeout,
    )
    result = runner.run(argv, cwd=cwd, stdin=stdin)
    out: dict[str, Any] = {
        "argv": result.argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.output_truncated:
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
    target = _resolve_within_impl(path, root)
    result = await asyncio.to_thread(
        _run_subprocess_impl,
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
    target = _resolve_within_impl(path, root)
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
    target = _resolve_within_impl(path, root)
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
        _run_subprocess_impl, argv, cwd=root, timeout=shell_timeout()
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
        _run_subprocess_impl,
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
    argv = _adapter_base_harden_git_argv(argv)
    return await _git(*argv, cwd=cwd)


def _harden_git_run_argv(argv: list[str]) -> list[str]:
    """Delegates to ``chio_adapter_base.security.harden_git_argv``.

    The canonical implementation returns a new list and never mutates the input.
    """
    return _adapter_base_harden_git_argv(argv)


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
