"""Output filters that drop forbidden entries from listings / search / diff.

This module hosts:

- :func:`forbidden_path_filter`: format-unaware partition into
  ``(kept, dropped)``. Each adapter that needs a format-aware splitter
  (porcelain status, git diff, FastAPI route table) ships its own
  splitter that produces the iterable of paths and reassembles the
  kept entries back into the format the consumer expects.

- :func:`filter_directory_entries`: format-aware wrapper for the
  ``{"path": ..., "entries": [...]}`` listing shape used by
  ``chio_file_list`` and similar handlers.

- :func:`filter_diff_output`: format-aware wrapper for git diff. Strips
  per-file hunks whose target path is forbidden.

- :func:`filter_status_output`: format-aware wrapper for git porcelain
  status. Drops rows whose left- or right-hand path is forbidden.

The format-aware wrappers all delegate the policy-check loop to
:func:`forbidden_path_filter`. Source of truth for the wrappers is
``sdks/python/chio-hermes/src/chio_hermes/handlers.py:291`` (plus the
diff hunk parser at line 563).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any


def forbidden_path_filter(
    entries: Iterable[str],
    *,
    is_forbidden: Callable[[str], bool],
) -> tuple[list[str], list[str]]:
    """Partition ``entries`` into ``(kept, dropped)``.

    Contract:

    - Input order is preserved in ``kept``.
    - ``dropped`` is in the order entries were rejected; the caller
      typically de-duplicates and sorts before logging.
    - ``is_forbidden`` is called once per entry. Exceptions raised by
      ``is_forbidden`` are NOT caught here; the caller must wrap if
      it wants conservative-deny semantics (chio-hermes treats
      exceptions as forbidden).

    Returns a new pair of lists; does not mutate ``entries``.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for entry in entries:
        if is_forbidden(entry):
            dropped.append(entry)
        else:
            kept.append(entry)
    return kept, dropped


def _strip_quotes(path: str) -> str:
    """Strip wrapping double-quotes from a porcelain path token.

    Porcelain quotes paths with unusual chars; the wrapping quotes are
    not part of the path itself.
    """
    text = path.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _parse_diff_git_header(line: str) -> str | None:
    """Parse ``diff --git a/<p> b/<p>`` and return the b path (or None).

    Mirrors ``chio_hermes.handlers._parse_diff_git_header``.
    """
    parts = line.strip().split()
    if len(parts) < 4:
        return None
    a_path = parts[2]
    b_path = parts[3]
    if a_path.startswith("a/"):
        a_path = a_path[2:]
    if b_path.startswith("b/"):
        b_path = b_path[2:]
    return b_path or a_path or None


def _split_git_diff_hunks(stdout: str) -> list[tuple[str | None, str]]:
    """Split a git diff into ``(path, hunk_text)`` pairs.

    ``path`` is ``None`` when the ``diff --git`` header is malformed.
    Mirrors ``chio_hermes.handlers._split_git_diff_hunks``.
    """
    if "diff --git" not in stdout:
        return []
    hunks: list[tuple[str | None, str]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current_lines:
                hunks.append((current_path, "".join(current_lines)))
            current_lines = [line]
            current_path = _parse_diff_git_header(line)
        else:
            current_lines.append(line)
    if current_lines:
        hunks.append((current_path, "".join(current_lines)))
    return hunks


def _is_forbidden_safe(
    is_forbidden: Callable[[str], bool], path: str
) -> bool:
    """Conservative wrapper: treat exceptions as forbidden.

    Mirrors the chio-hermes ``_is_read_forbidden`` semantics where any
    unexpected error from the policy check is treated as a denial.
    """
    try:
        return bool(is_forbidden(path))
    except Exception:  # noqa: BLE001 - conservative deny on policy error
        return True


def filter_directory_entries(
    result: dict[str, Any],
    *,
    is_forbidden: Callable[[str], bool],
    listing_root: str | None = None,
) -> dict[str, Any]:
    """Drop forbidden entries from a ``{"path": ..., "entries": [...]}`` dict.

    The ``is_forbidden`` callable receives a path joined under
    ``result["path"]`` (or ``listing_root`` if ``path`` is missing). On
    no-op (nothing dropped), the input dict is returned unchanged for
    object-identity-friendly hot paths. Otherwise a fresh dict is
    returned with ``entries`` replaced and a sorted unique list of
    rejected names under ``forbidden_paths_filtered``.

    Mirrors ``chio_hermes.handlers._filter_directory_entries``.
    """
    entries = result.get("entries")
    if not isinstance(entries, list):
        return result
    base = result.get("path") or listing_root or ""
    base_path = Path(str(base))
    kept: list[Any] = []
    dropped: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            kept.append(entry)
            continue
        child = str(base_path / entry)
        if _is_forbidden_safe(is_forbidden, child):
            dropped.append(entry)
            continue
        kept.append(entry)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["entries"] = kept
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


def filter_diff_output(
    result: dict[str, Any],
    *,
    is_forbidden: Callable[[str], bool],
) -> dict[str, Any]:
    """Strip per-file hunks for forbidden paths from a git diff result.

    Operates on the ``{"stdout": ..., "returncode": ...}`` envelope that
    chio-hermes executors emit. Returns the input unchanged when
    ``stdout`` is missing, empty, or contains no ``diff --git`` header.
    Mirrors ``chio_hermes.handlers._filter_diff_output``.
    """
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout:
        return result
    hunks = _split_git_diff_hunks(stdout)
    if not hunks:
        return result
    kept: list[str] = []
    dropped: list[str] = []
    for path, body in hunks:
        if path is None:
            dropped.append("<malformed-diff-header>")
            continue
        if path is not None and _is_forbidden_safe(is_forbidden, path):
            dropped.append(path)
            continue
        kept.append(body)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["stdout"] = "".join(kept)
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


def filter_status_output(
    result: dict[str, Any],
    *,
    is_forbidden: Callable[[str], bool],
) -> dict[str, Any]:
    """Drop porcelain rows whose path or rename target is forbidden.

    Operates on the ``{"stdout": ..., "returncode": ...}`` envelope.
    Porcelain v1 lines are ``XY <path>`` or rename
    ``XY <old> -> <new>``. The row is dropped when either side fails
    the policy check. Returns the input unchanged when nothing was
    dropped. Mirrors ``chio_hermes.handlers._filter_status_output``.
    """
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout:
        return result
    kept_lines: list[str] = []
    dropped: list[str] = []
    for raw_line in stdout.splitlines():
        if len(raw_line) < 4:
            kept_lines.append(raw_line)
            continue
        body = raw_line[3:]
        if " -> " in body:
            old, new = body.split(" -> ", 1)
            paths = [_strip_quotes(old), _strip_quotes(new)]
        else:
            paths = [_strip_quotes(body)]
        forbidden = [p for p in paths if _is_forbidden_safe(is_forbidden, p)]
        if forbidden:
            dropped.extend(forbidden)
            continue
        kept_lines.append(raw_line)
    if not dropped:
        return result
    filtered = dict(result)
    filtered["stdout"] = "\n".join(kept_lines) + ("\n" if kept_lines else "")
    filtered["forbidden_paths_filtered"] = sorted(set(dropped))
    return filtered


__all__ = [
    "filter_diff_output",
    "filter_directory_entries",
    "filter_status_output",
    "forbidden_path_filter",
]
