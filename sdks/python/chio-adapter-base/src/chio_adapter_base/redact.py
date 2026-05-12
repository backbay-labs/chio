"""Per-tool argument body redaction for Chio adapter receipts.

This module hosts:

- :func:`redact_args`: replace tool-arg fields that carry raw bodies (the
  ``content`` of ``chio_file_write``, the ``patch`` of ``chio_file_edit``)
  with a byte-count stub so embedded secrets do not land in the receipt
  log. Path / message fields are preserved.
- :class:`RedactionPolicy`: frozen mapping from tool-name to the tuple of
  arg-fields to redact.

The chio-hermes default policy redacts:

    {
        "chio_file_write": ("content",),
        "chio_file_edit": ("patch",),
    }

Sibling adapters can extend this with their own tool names by passing a
custom :class:`RedactionPolicy` to :func:`redact_args`. The class
:class:`RedactArgs` is a callable wrapper around :func:`redact_args` for
adapters that want to pre-bake a policy table at construction time.

Source of truth (chio-hermes 0.1.0): ``_redact_args`` and
``_BODY_REDACT_FIELDS`` in
``sdks/python/chio-hermes/src/chio_hermes/hooks.py:140``.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

# Mirror of ``chio_hermes.hooks._BODY_REDACT_FIELDS``. Kept here as the
# default so adapters that import :func:`redact_args` without a policy
# get the chio baseline behaviour.
_CHIO_DEFAULT_BODY_FIELDS: dict[str, tuple[str, ...]] = {
    "chio_file_write": ("content",),
    "chio_file_edit": ("patch",),
}


@dataclasses.dataclass(frozen=True)
class RedactionPolicy:
    """Mapping from tool-name to the tuple of arg-fields to redact.

    Frozen so callers can share a single policy instance across hooks
    without worrying about mutation. Use :meth:`chio_default` for the
    chio-hermes baseline; sibling adapters extend by constructing with
    a custom mapping.
    """

    body_fields: Mapping[str, tuple[str, ...]]

    @classmethod
    def chio_default(cls) -> RedactionPolicy:
        """Return the chio-hermes baseline policy.

        Mirrors ``_BODY_REDACT_FIELDS`` in
        ``sdks/python/chio-hermes/src/chio_hermes/hooks.py:143``.
        """
        return cls(body_fields=dict(_CHIO_DEFAULT_BODY_FIELDS))


def _byte_count(value: Any) -> int:
    """Return the utf-8 byte count of ``value`` for the omission stub.

    ``str`` -> utf-8 encoded length.
    ``bytes`` / ``bytearray`` -> ``len`` directly.
    Anything else -> coerced via ``str()`` then encoded; ``-1`` on failure.
    """
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    try:
        return len(str(value).encode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - defensive
        return -1


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

    Behaviour notes:

    - When ``policy`` is ``None``, fall back to
      :meth:`RedactionPolicy.chio_default`.
    - When ``tool_name`` is ``None`` or unknown, return a shallow copy
      of ``args`` unchanged.
    - When the field is absent from ``args``, it stays absent (no stub
      is inserted).
    - The returned dict is always a fresh ``dict``; callers can mutate
      it freely.
    """
    effective_policy = policy if policy is not None else RedactionPolicy.chio_default()
    fields = effective_policy.body_fields.get(tool_name or "")
    if not fields:
        return dict(args)
    redacted: dict[str, Any] = dict(args)
    for field in fields:
        if field not in redacted:
            continue
        redacted[field] = {
            "omitted": True,
            "byte_count": _byte_count(redacted[field]),
        }
    return redacted


class RedactArgs:
    """Callable redactor that pre-binds a :class:`RedactionPolicy`.

    Adapters that want a single, table-driven instance to thread through
    their hook layer can construct one of these once and call it like a
    function::

        redact = RedactArgs({"my_tool": ("body",)})
        redacted = redact("my_tool", {"body": "..."})

    The callable form is what the conformance suite asserts against.
    """

    def __init__(
        self, body_redact_fields: Mapping[str, tuple[str, ...]]
    ) -> None:
        # Freeze into a dict copy so callers cannot mutate after binding.
        self._policy = RedactionPolicy(body_fields=dict(body_redact_fields))

    @property
    def policy(self) -> RedactionPolicy:
        """The bound :class:`RedactionPolicy`."""
        return self._policy

    def __call__(
        self, tool_name: str | None, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        return redact_args(tool_name, args, policy=self._policy)


__all__ = [
    "RedactArgs",
    "RedactionPolicy",
    "redact_args",
]
