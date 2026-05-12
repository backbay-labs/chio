"""Subprocess and shell hardening primitives shared across Chio adapters.

This module is the future home of:

- ``sanitised_env``: scrub credential-bearing environment variables
  before subprocess spawn. Source of truth: ``_sanitised_env`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:94``, alongside
  the ``_ENV_DENY_PREFIXES`` / ``_ENV_DENY_SUFFIXES`` /
  ``_ENV_DENY_EXACT`` tables.

- ``harden_git_argv``: defense-in-depth ``--no-verify`` injection on
  ``git commit`` invocations and rejection of explicit ``--verify``.
  Source of truth: ``_harden_git_run_argv`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:401``.

- ``reject_shell_argv_escape``: reject argv tokens containing ``..``
  segments or absolute paths that resolve outside the workspace root.
  Source of truth: ``_reject_shell_argv_escape`` in
  ``sdks/python/chio-hermes/src/chio_hermes/handlers.py:408``.

- ``BoundedSubprocess``: spawn via ``Popen`` with per-stream byte caps
  drained by reader threads, so a chatty child cannot OOM the host
  process and a full pipe cannot block ``wait()``. Source of truth:
  ``_drain_stream_to_cap`` and ``_run_subprocess`` in
  ``sdks/python/chio-hermes/src/chio_hermes/executors.py:148``.

Phase 1 (this scaffold) ships only the public type signatures. Phase 2
ports the implementations from chio-hermes verbatim, then wraps them
in tests and migrates chio-hermes itself to import from here.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Callable, Mapping

DEFAULT_SHELL_TIMEOUT: int = 60
"""Mirror of ``chio_hermes.executors.DEFAULT_SHELL_TIMEOUT``."""

DEFAULT_SUBPROCESS_MAX_BYTES: int = 1 << 20  # 1 MiB
"""Mirror of ``chio_hermes.executors.DEFAULT_SUBPROCESS_MAX_BYTES``."""


def sanitised_env(*, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``base`` (default ``os.environ``) with secrets removed.

    Drops keys matching any of:

    - prefixes: ``CHIO_``, ``HERMES_``, ``AWS_``, ``GOOGLE_``, ``GCP_``,
      ``AZURE_``, ``OPENAI_``, ``ANTHROPIC_``, ``GEMINI_``, ``GH_``,
      ``GITHUB_``, ``GIT_AUTH_``, ``GIT_CONFIG_``, ``VAULT_``,
      ``DATABRICKS_``, ``HF_``, ``HUGGINGFACE_``
    - suffixes: ``_API_KEY``, ``_TOKEN``, ``_SECRET``, ``_PASSWORD``,
      ``_PASSWD``, ``_PRIVATE_KEY``, ``_CREDENTIALS``, ``_CREDS``
    - exact names: see ``_ENV_DENY_EXACT`` in chio-hermes

    The exact lists live in
    ``sdks/python/chio-hermes/src/chio_hermes/executors.py``; the Phase 2
    port copies them verbatim and the conformance test asserts byte-for-
    byte parity.
    """
    raise NotImplementedError(
        "Phase 2: port from chio_hermes.executors._sanitised_env"
    )


def harden_git_argv(argv: list[str]) -> list[str]:
    """Inject ``--no-verify`` into ``git commit`` argv; reject ``--verify``.

    Mirrors ``_harden_git_run_argv`` from chio-hermes:

    - Locate the ``commit`` subcommand (which may follow leading global
      options like ``-c name=value``).
    - If ``--verify`` is in the tail, raise ``PermissionError`` (the
      caller is trying to override the hardening).
    - If ``--no-verify`` is already there, return ``argv`` unchanged.
    - Otherwise insert ``--no-verify`` immediately after ``commit``.

    Returns a new list; does not mutate ``argv``.
    """
    raise NotImplementedError(
        "Phase 2: port from chio_hermes.executors._harden_git_run_argv"
    )


def reject_shell_argv_escape(
    command: str, *, root: pathlib.Path | str | None
) -> None:
    """Best-effort reject argv tokens that escape the workspace.

    Splits ``command`` with ``shlex``. For each token:

    - if any ``/``-separated segment equals ``..``, raise.
    - if the token is an absolute path and ``root`` is provided, resolve
      it and raise unless it lives under ``root``.

    On malformed shlex quoting, returns silently and lets the executor
    surface the syntax error rather than masking it as a path escape.
    Source of truth: ``_reject_shell_argv_escape`` in
    ``sdks/python/chio-hermes/src/chio_hermes/handlers.py:408``.
    """
    raise NotImplementedError(
        "Phase 2: port from chio_hermes.handlers._reject_shell_argv_escape"
    )


@dataclasses.dataclass(frozen=True)
class BoundedSubprocessResult:
    """Result of a ``BoundedSubprocess.run`` invocation.

    Mirrors the dict shape returned by chio-hermes's ``_run_subprocess``
    but as a typed dataclass so consumers can rely on field names.
    """

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    output_truncated: bool
    timed_out: bool


class BoundedSubprocess:
    """Spawn child processes with bounded stdout/stderr capture.

    The crucial behaviour (from chio-hermes ``_drain_stream_to_cap``):
    keep draining each pipe past the cap so the producer does not block
    on a full pipe (which would cause ``wait()`` to time out even when
    the cap was meant to be the bound). Bytes past the cap are
    discarded, ``output_truncated=True`` is set on the result.

    Args:
      max_bytes: per-stream cap. Defaults to ``DEFAULT_SUBPROCESS_MAX_BYTES``
        unless overridden via the ``CHIO_SUBPROCESS_MAX_BYTES`` env var
        (resolved by the Phase 2 implementation).
      timeout_seconds: ``Popen.wait`` timeout. Defaults to
        ``DEFAULT_SHELL_TIMEOUT`` (overridable via ``CHIO_SHELL_TIMEOUT``).
      env_factory: callable returning the environment dict. Defaults to
        ``sanitised_env``. Override only when the caller has a stricter
        environment policy than the chio default.
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

    def run(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path | str,
        stdin: str | None = None,
    ) -> BoundedSubprocessResult:
        """Run ``argv`` synchronously with bounded capture.

        Phase 2 ports ``chio_hermes.executors._run_subprocess`` verbatim
        and wraps the result dict in :class:`BoundedSubprocessResult`.
        """
        _ = (argv, cwd, stdin)
        raise NotImplementedError(
            "Phase 2: port from chio_hermes.executors._run_subprocess"
        )

    async def arun(
        self,
        argv: list[str],
        *,
        cwd: pathlib.Path | str,
        stdin: str | None = None,
    ) -> BoundedSubprocessResult:
        """Async wrapper around :meth:`run` via ``asyncio.to_thread``.

        Mirrors how chio-hermes's executors call ``asyncio.to_thread`` on
        ``_run_subprocess``. The actual subprocess work runs on a worker
        thread; this method only awaits the result.
        """
        _ = (argv, cwd, stdin)
        raise NotImplementedError(
            "Phase 2: wrap BoundedSubprocess.run with asyncio.to_thread"
        )


__all__ = [
    "DEFAULT_SHELL_TIMEOUT",
    "DEFAULT_SUBPROCESS_MAX_BYTES",
    "BoundedSubprocess",
    "BoundedSubprocessResult",
    "harden_git_argv",
    "reject_shell_argv_escape",
    "sanitised_env",
]
