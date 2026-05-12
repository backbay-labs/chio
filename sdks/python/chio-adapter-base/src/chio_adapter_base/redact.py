"""Per-tool argument body redaction for Chio adapter receipts.

This module is the future home of:

- ``redact_args``: replace tool-arg fields that carry raw bodies (the
  ``content`` of ``chio_file_write``, the ``patch`` of
  ``chio_file_edit``) with a byte-count stub so embedded secrets do
  not land in the receipt log. Path / message fields are preserved.
  Source of truth: ``_redact_args`` and ``_BODY_REDACT_FIELDS`` in
  ``sdks/python/chio-hermes/src/chio_hermes/hooks.py:140``.

The chio-hermes default policy redacts:

    {
        "chio_file_write": ("content",),
        "chio_file_edit": ("patch",),
    }

Sibling adapters can extend this with their own tool names. For
example, chio-langchain might add ``("langchain_file_write", ("body",))``.
The :class:`RedactionPolicy` carries the mapping so the redaction
behaviour is testable and explicit.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any


@dataclasses.dataclass(frozen=True)
class RedactionPolicy:
    """Mapping from tool-name to the tuple of arg-fields to redact.

    Frozen so callers can share a single policy instance across hooks
    without worrying about mutation. Use :meth:`chio_default` for the
    chio-hermes baseline; sibling adapters extend by passing a custom
    policy to :func:`redact_args`.
    """

    body_fields: Mapping[str, tuple[str, ...]]

    @classmethod
    def chio_default(cls) -> RedactionPolicy:
        """The chio-hermes baseline policy.

        Mirrors ``_BODY_REDACT_FIELDS`` in
        ``sdks/python/chio-hermes/src/chio_hermes/hooks.py:143``.
        Phase 2 will return the same dict literal so changes track
        the chio-hermes source.
        """
        raise NotImplementedError(
            "Phase 2: return the chio_hermes _BODY_REDACT_FIELDS map"
        )


def redact_args(
    tool_name: str | None,
    args: Mapping[str, Any],
    *,
    policy: RedactionPolicy | None = None,
) -> dict[str, Any]:
    """Return a copy of ``args`` with body fields replaced by a stub.

    For each field listed by ``policy.body_fields[tool_name]``, the
    field is replaced with::

        {"omitted": True, "byte_count": <len-in-utf8-bytes>}

    Notes the Phase 2 implementation must preserve:

    - When ``policy`` is ``None``, fall back to
      :meth:`RedactionPolicy.chio_default`.
    - When ``tool_name`` is ``None`` or unknown, return a shallow copy
      of ``args`` unchanged.
    - When the field value is ``str``, count utf-8 bytes; ``bytes`` /
      ``bytearray`` use ``len`` directly; other types are coerced via
      ``str()``-then-encode and fall back to ``-1`` on encoding error.
    - The returned dict is always a fresh ``dict``; callers can mutate
      it freely.
    """
    _ = (tool_name, args, policy)
    raise NotImplementedError(
        "Phase 2: port from chio_hermes.hooks._redact_args"
    )


__all__ = [
    "RedactionPolicy",
    "redact_args",
]
