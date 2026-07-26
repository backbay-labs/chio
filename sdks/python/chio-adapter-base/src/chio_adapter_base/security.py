"""Subprocess and shell hardening primitives shared across Chio adapters.

This module hosts:

- :func:`sanitised_env`: scrub credential-bearing environment variables
  before subprocess spawn. Source of truth: ``_sanitised_env`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:94``, alongside
  the ``_ENV_DENY_PREFIXES`` / ``_ENV_DENY_SUFFIXES`` /
  ``_ENV_DENY_EXACT`` tables.

- :func:`harden_git_argv`: defense-in-depth ``--no-verify`` injection
  on ``git commit`` invocations and rejection of explicit ``--verify``.
  Source of truth: ``_harden_git_run_argv`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:401``.

- :func:`reject_shell_argv_escape`: reject argv tokens containing
  ``..`` segments or absolute paths that resolve outside the workspace
  root. Source of truth: ``_reject_shell_argv_escape`` in
  ``sdks/python/chio-hermes/src/chio_hermes/handlers.py:408``.

- :func:`resolve_within`: resolve a path and confirm it lives inside a
  workspace root (lexical fallback when the target does not exist).
  Source of truth: ``_resolve_within`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:128``.

- :class:`BoundedSubprocess`: spawn via ``Popen`` with per-stream byte
  caps drained by reader threads, so a chatty child cannot OOM the
  host process and a full pipe cannot block ``wait()``. Source of
  truth: ``_drain_stream_to_cap`` and ``_run_subprocess`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:148``.

- :exc:`ChioPathEscapeError`: raised by :func:`reject_shell_argv_escape`
  on a ``..``-bearing or out-of-workspace token. A ``PermissionError``
  subclass so adapters that already catch ``PermissionError`` keep
  working.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import pathlib
import re
import shlex
import subprocess
import threading
from collections.abc import Callable, Iterator, Mapping
from typing import IO

DEFAULT_SHELL_TIMEOUT: int = 60
"""Mirror of ``chio_hermes.executors.DEFAULT_SHELL_TIMEOUT``."""

DEFAULT_SUBPROCESS_MAX_BYTES: int = 1 << 20  # 1 MiB
"""Mirror of ``chio_hermes.executors.DEFAULT_SUBPROCESS_MAX_BYTES``."""


# Credential-carrying env vars stripped from child processes. Mirror of
# ``chio_hermes.executors._ENV_DENY_PREFIXES``.
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
    # GIT_CONFIG_* lets a parent process inject ``core.hooksPath``,
    # ``include.path``, etc. into every git invocation, defeating the
    # ``--no-verify`` hardening.
    "GIT_CONFIG_",
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
        # Git environment overrides that defeat workspace anchoring or
        # hook execution hardening (``--no-verify``).
        "GIT_HOOKS_PATH",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_OBJECT_DIRECTORY",
    }
)

_WINDOWS_ABSOLUTE_BARE_START_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z]:(?:[\\]|/(?!/))"
    r"|(?<!:)\\\\(?=[^\\/\s\"']+[\\/][^\\/\s\"'])"
    r"|(?<!:)//(?=[^/\s\"']+/[^/\s\"'])"
)
_WINDOWS_ABSOLUTE_EMBEDDED_START_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z]:(?:[\\]|/(?!/))"
    r"|(?<!:)\\\\(?=[^\\/]+[\\/][^\\/]+)"
    r"|(?<!:)//(?=[^/]+/[^/]+)"
)
_WINDOWS_ABSOLUTE_LIST_BOUNDARIES = frozenset("=,;| \t\r\n\"'")
_WINDOWS_ABSOLUTE_LIST_SUFFIX = " \t\r\n,;|\"'[](){}"
_SSH_REMOTE_COMMANDS: frozenset[str] = frozenset({"scp", "rsync", "sftp"})
_SSH_REMOTE_SPEC_RE = re.compile(r"^(?:[^@\s:/]+@)?[A-Za-z][A-Za-z0-9_.-]*:.+")


class ChioPathEscapeError(PermissionError):
    """Raised when a shell argv token escapes the workspace root.

    Subclass of ``PermissionError`` so adapters that already catch the
    builtin keep working. The ``token`` attribute is the offending
    argv element; ``reason`` is one of ``"dotdot_segment"`` or
    ``"outside_workspace"``.
    """

    def __init__(self, token: str, reason: str, *, message: str | None = None) -> None:
        self.token = token
        self.reason = reason
        super().__init__(message or f"shell argv token {token!r} ({reason}) escapes the workspace")


def _is_denied_env(name: str) -> bool:
    """Return True if the env var ``name`` carries credentials."""
    upper = name.upper()
    if upper in _ENV_DENY_EXACT:
        return True
    if any(upper.startswith(prefix) for prefix in _ENV_DENY_PREFIXES):
        return True
    if any(upper.endswith(suffix) for suffix in _ENV_DENY_SUFFIXES):
        return True
    return False


def _reject_windows_absolute_escape(token: str, root: str) -> None:
    normalised = token.replace("\\", "/")
    if any(seg == ".." for seg in normalised.split("/")):
        raise ChioPathEscapeError(token, "dotdot_segment")

    token_path = pathlib.PureWindowsPath(token)
    root_path = pathlib.PureWindowsPath(root)
    if not token_path.is_absolute() or not root_path.is_absolute():
        raise ChioPathEscapeError(token, "outside_workspace")

    token_parts = tuple(part.casefold() for part in token_path.parts)
    root_parts = tuple(part.casefold() for part in root_path.parts)
    if len(token_parts) < len(root_parts) or token_parts[: len(root_parts)] != root_parts:
        raise ChioPathEscapeError(token, "outside_workspace")


def _iter_windows_absolute_candidates(
    text: str,
    start_pattern: re.Pattern[str],
    *,
    stop_at_shell_boundary: bool,
) -> Iterator[str]:
    starts: list[re.Match[str]] = []
    for start in start_pattern.finditer(text):
        is_unc = text.startswith(("\\\\", "//"), start.start())
        if is_unc and starts:
            previous_to_current = text[starts[-1].end() : start.start()]
            starts_new_shell_token = stop_at_shell_boundary and bool(
                re.search(r"[\s\"']", previous_to_current)
            )
            has_list_boundary = (
                start.start() > 0
                and text[start.start() - 1] in _WINDOWS_ABSOLUTE_LIST_BOUNDARIES
            )
            if not starts_new_shell_token and not has_list_boundary:
                continue
        starts.append(start)

    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        if stop_at_shell_boundary:
            boundary = re.search(r"[\s\"']", text[start.end() : end])
            if boundary is not None:
                end = start.end() + boundary.start()
        candidate = text[start.start() : end]
        if index + 1 < len(starts):
            candidate = candidate.rstrip(_WINDOWS_ABSOLUTE_LIST_SUFFIX)
        yield candidate


def _without_quoted_shell_spans(command: str) -> str:
    chars: list[str] = []
    quote: str | None = None
    for ch in command:
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                chars.append(" ")
            else:
                chars.append(ch)
            continue

        chars.append(" ")
        if ch == quote:
            quote = None
    return "".join(chars)


def _is_windows_absolute_root(root: str) -> bool:
    root_path = pathlib.PureWindowsPath(root)
    return bool(root_path.drive) and root_path.is_absolute()


def _ssh_remote_tokens(argv: list[str], root_text: str | None) -> frozenset[str]:
    if root_text is None or _is_windows_absolute_root(root_text) or not argv:
        return frozenset()
    command = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if command not in _SSH_REMOTE_COMMANDS:
        return frozenset()
    return frozenset(token for token in argv[1:] if _SSH_REMOTE_SPEC_RE.match(token))


def _is_ssh_remote_windows_candidate(
    candidate: str,
    remote_tokens: frozenset[str],
) -> bool:
    return candidate in remote_tokens or any(
        remote.endswith(f"@{candidate}") for remote in remote_tokens
    )


def sanitised_env(*, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``base`` (default ``os.environ``) with secrets removed.

    Drops keys matching any prefix in ``_ENV_DENY_PREFIXES``, any suffix
    in ``_ENV_DENY_SUFFIXES``, or any exact name in ``_ENV_DENY_EXACT``.
    The match is case-insensitive on the key (uppercased before
    comparison).
    """
    source = base if base is not None else os.environ
    return {k: v for k, v in source.items() if not _is_denied_env(k)}


_GIT_GLOBAL_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    }
)


def harden_git_argv(argv: list[str]) -> list[str]:
    """Inject ``--no-verify`` into ``git commit`` argv; reject ``--verify``.

    Mirrors ``chio_hermes.executors._harden_git_run_argv``:

    - Locate the ``commit`` subcommand (which may follow leading global
      options like ``-c name=value``).
    - If ``--verify`` is in the tail, raise ``PermissionError`` (the
      caller is trying to override the hardening).
    - If ``--no-verify`` is already there, return ``argv`` unchanged.
    - Otherwise insert ``--no-verify`` immediately after ``commit``.

    Returns a new list; does not mutate ``argv``.
    """
    subcommand_idx = _git_subcommand_index(argv)
    if subcommand_idx is None or argv[subcommand_idx] != "commit":
        return list(argv)
    tail = argv[subcommand_idx + 1 :]
    if "--verify" in tail:
        raise PermissionError(
            "git_run: explicit --verify is forbidden; "
            "commit hooks must stay disabled (use a shell tool for hooks)"
        )
    if "--no-verify" in tail:
        return list(argv)
    return [*argv[: subcommand_idx + 1], "--no-verify", *tail]


def _git_subcommand_index(argv: list[str]) -> int | None:
    executable_name = (
        argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower() if argv else ""
    )
    index = 1 if executable_name in {"git", "git.exe"} else 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            return None
        if arg in ("-C", "-c"):
            index += 2
            continue
        if (arg.startswith("-C") or arg.startswith("-c")) and len(arg) > 2:
            index += 1
            continue
        if arg in _GIT_GLOBAL_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(
            arg.startswith(f"{option}=")
            for option in _GIT_GLOBAL_OPTIONS_WITH_VALUES
        ):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return index
    return None


def reject_shell_argv_escape(
    command: str, *, root: pathlib.Path | str | None
) -> None:
    """Best-effort reject argv tokens that escape the workspace.

    Splits ``command`` with ``shlex``. For each token:

    - if any ``/``-separated segment equals ``..``, raise
      :exc:`ChioPathEscapeError`.
    - if the token is an absolute path and ``root`` is provided, resolve
      it and raise unless it lives under ``root``.

    On malformed shlex quoting, returns silently and lets the executor
    surface the syntax error rather than masking it as a path escape.
    """
    try:
        argv = shlex.split(command or "")
    except ValueError:
        return
    root_text = str(root) if root is not None else None
    root_path = pathlib.Path(root_text).resolve() if root_text is not None else None
    ssh_remote_tokens = _ssh_remote_tokens(argv, root_text)
    if root_path is not None:
        unquoted_command = _without_quoted_shell_spans(command or "")
        for candidate in _iter_windows_absolute_candidates(
            unquoted_command,
            _WINDOWS_ABSOLUTE_BARE_START_RE,
            stop_at_shell_boundary=True,
        ):
            if _is_ssh_remote_windows_candidate(candidate, ssh_remote_tokens):
                continue
            _reject_windows_absolute_escape(
                candidate,
                root_text or "",
            )
    for token in argv:
        normalised = token.replace("\\", "/")
        segments = normalised.split("/")
        if any(seg == ".." for seg in segments):
            raise ChioPathEscapeError(token, "dotdot_segment")
        if root_text is not None:
            for candidate in _iter_windows_absolute_candidates(
                token,
                _WINDOWS_ABSOLUTE_EMBEDDED_START_RE,
                stop_at_shell_boundary=False,
            ):
                if _is_ssh_remote_windows_candidate(candidate, ssh_remote_tokens):
                    continue
                _reject_windows_absolute_escape(
                    candidate,
                    root_text,
                )
        is_windows_absolute = (
            len(normalised) >= 3
            and normalised[0].isalpha()
            and normalised[1] == ":"
            and normalised[2] == "/"
        ) or normalised.startswith("//")
        if root_text is not None and is_windows_absolute:
            if _is_ssh_remote_windows_candidate(token, ssh_remote_tokens):
                continue
            _reject_windows_absolute_escape(token, root_text)
            continue
        is_absolute_token = normalised.startswith("/")
        if root_path is not None and is_absolute_token:
            try:
                resolved = pathlib.Path(token).resolve()
            except OSError as exc:
                raise ChioPathEscapeError(token, "outside_workspace") from exc
            try:
                resolved.relative_to(root_path)
            except ValueError as exc:
                raise ChioPathEscapeError(token, "outside_workspace") from exc


def resolve_within(
    path: pathlib.Path | str, root: pathlib.Path
) -> pathlib.Path:
    """Resolve ``path`` and confirm it lives inside ``root``.

    Raises ``PermissionError`` if the resolved path escapes ``root``.
    Falls back to a lexical normpath when the target does not exist
    (which covers ``chio_file_write`` to a not-yet-created file).
    Mirrors ``chio_hermes.executors._resolve_within``.
    """
    candidate = pathlib.Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        resolved = pathlib.Path(os.path.normpath(str(candidate)))
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError(
            f"path {str(path)!r} resolves outside the workspace root"
        ) from exc
    return resolved


@dataclasses.dataclass(frozen=True)
class BoundedSubprocessResult:
    """Result of a :meth:`BoundedSubprocess.run` invocation.

    Mirrors the dict shape returned by chio-hermes's ``_run_subprocess``
    but as a typed dataclass so consumers can rely on field names.
    ``stdout`` / ``stderr`` are decoded utf-8 with ``errors="replace"``
    so the result is always JSON-serialisable.
    """

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    output_truncated: bool
    timed_out: bool


def _drain_stream_to_cap(
    stream: IO[bytes] | None, cap: int
) -> tuple[bytearray, bool]:
    """Drain ``stream`` to a bytearray, capped at ``cap`` bytes.

    Continues draining past the cap so the producer does not block on a
    full pipe (which would cause the surrounding ``wait()`` to time out
    even when the cap was meant to be the bound). Bytes past the cap
    are discarded. Mirrors ``chio_hermes.executors._drain_stream_to_cap``.
    """
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


def _resolve_subprocess_max_bytes(default: int) -> int:
    """Resolve ``CHIO_SUBPROCESS_MAX_BYTES`` env var or fall back to ``default``."""
    raw = os.environ.get("CHIO_SUBPROCESS_MAX_BYTES")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _resolve_shell_timeout(default: int) -> int:
    """Resolve ``CHIO_SHELL_TIMEOUT`` env var or fall back to ``default``."""
    raw = os.environ.get("CHIO_SHELL_TIMEOUT")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


class BoundedSubprocess:
    """Spawn child processes with bounded stdout/stderr capture.

    The crucial behaviour (from chio-hermes ``_drain_stream_to_cap``):
    keep draining each pipe past the cap so the producer does not block
    on a full pipe. Bytes past the cap are discarded;
    ``output_truncated=True`` is set on the result.

    Args:
      max_bytes: per-stream cap. ``None`` resolves
        ``CHIO_SUBPROCESS_MAX_BYTES`` at call time, falling back to
        :data:`DEFAULT_SUBPROCESS_MAX_BYTES`.
      timeout_seconds: ``Popen.wait`` timeout. ``None`` resolves
        ``CHIO_SHELL_TIMEOUT`` at call time, falling back to
        :data:`DEFAULT_SHELL_TIMEOUT`.
      env_factory: callable returning the environment dict. Defaults to
        :func:`sanitised_env`. Override only when the caller has a
        stricter environment policy than the chio default.
    """

    def __init__(
        self,
        *,
        max_bytes: int | None = None,
        timeout_seconds: int | None = None,
        env_factory: Callable[[], Mapping[str, str]] | None = None,
    ) -> None:
        self._max_bytes = max_bytes
        self._timeout_seconds = timeout_seconds
        self._env_factory = env_factory

    def _effective_cap(self) -> int:
        if self._max_bytes is not None:
            return self._max_bytes
        return _resolve_subprocess_max_bytes(DEFAULT_SUBPROCESS_MAX_BYTES)

    def _effective_timeout(self) -> int:
        if self._timeout_seconds is not None:
            return self._timeout_seconds
        return _resolve_shell_timeout(DEFAULT_SHELL_TIMEOUT)

    def _effective_env(self) -> Mapping[str, str]:
        if self._env_factory is None:
            return sanitised_env()
        return self._env_factory()

    def run(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path | str,
        stdin: str | None = None,
    ) -> BoundedSubprocessResult:
        """Run ``argv`` synchronously with bounded capture.

        Raises ``subprocess.TimeoutExpired`` on timeout (mirrors the
        chio-hermes contract; a silent ``returncode=-9`` would mask the
        timeout from the caller).
        """
        cap = self._effective_cap()
        timeout = self._effective_timeout()
        env = dict(self._effective_env())

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

        def _reader(name: str, stream: IO[bytes] | None) -> None:
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
            raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

        stdout_buf, stdout_truncated = drained["stdout"]
        stderr_buf, stderr_truncated = drained["stderr"]
        return BoundedSubprocessResult(
            argv=list(argv),
            returncode=proc.returncode,
            stdout=stdout_buf.decode("utf-8", errors="replace"),
            stderr=stderr_buf.decode("utf-8", errors="replace"),
            output_truncated=stdout_truncated or stderr_truncated,
            timed_out=False,
        )

    async def arun(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path | str,
        stdin: str | None = None,
    ) -> BoundedSubprocessResult:
        """Async wrapper around :meth:`run` via ``asyncio.to_thread``.

        Mirrors how chio-hermes's executors call ``asyncio.to_thread``
        on ``_run_subprocess``. The actual subprocess work runs on a
        worker thread; this method only awaits the result.
        """
        return await asyncio.to_thread(self.run, argv, cwd=cwd, stdin=stdin)


__all__ = [
    "DEFAULT_SHELL_TIMEOUT",
    "DEFAULT_SUBPROCESS_MAX_BYTES",
    "BoundedSubprocess",
    "BoundedSubprocessResult",
    "ChioPathEscapeError",
    "harden_git_argv",
    "reject_shell_argv_escape",
    "resolve_within",
    "sanitised_env",
]
