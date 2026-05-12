"""Output filters that drop forbidden entries from listings / search / diff.

This module is the future home of:

- ``forbidden_path_filter``: given an iterable of path entries and a
  ``is_forbidden`` callable, partition into ``(kept, dropped)``. The
  chio-hermes implementations of ``_filter_directory_entries``,
  ``_filter_search_matches``, ``_filter_status_output``, and
  ``_filter_diff_output`` (in
  ``sdks/python/chio-hermes/src/chio_hermes/handlers.py:291``) become
  thin format-aware wrappers around this primitive plus a parser.

The primitive itself is intentionally format-unaware: it does not
know about porcelain rows, diff hunks, or FastAPI route tables. Each
adapter ships its own splitter that produces the iterable of paths
and reassembles the kept entries back into the format the consumer
expects. That keeps this module small and lets adapters with very
different output shapes still share the policy-check loop.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable


def forbidden_path_filter(
    entries: Iterable[str],
    *,
    is_forbidden: Callable[[str], bool],
) -> tuple[list[str], list[str]]:
    """Partition ``entries`` into ``(kept, dropped)``.

    Phase 2 contract:

    - Input order is preserved in ``kept`` (callers reassemble in
      original order).
    - ``dropped`` is in the order entries were rejected; the caller
      typically de-duplicates and sorts before logging
      (see ``forbidden_paths_filtered`` in chio-hermes).
    - ``is_forbidden`` is called once per entry. Exceptions raised by
      ``is_forbidden`` are NOT caught here; the caller must wrap if
      it wants conservative-deny semantics (chio-hermes treats
      exceptions as forbidden).

    Returns a new pair of lists; does not mutate ``entries``.
    """
    _ = (entries, is_forbidden)
    raise NotImplementedError(
        "Phase 2: port from the chio_hermes.handlers _filter_* helpers"
    )


__all__ = [
    "forbidden_path_filter",
]
