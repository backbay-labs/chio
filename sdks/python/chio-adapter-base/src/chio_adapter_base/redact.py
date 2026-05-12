"""Per-tool argument body redaction for Chio adapter receipts.

This module hosts:

- :func:`redact_args`: replace tool-arg fields that carry raw bodies (the
  ``content`` of ``chio_file_write``, the ``patch`` of ``chio_file_edit``)
  with a byte-count stub so embedded secrets do not land in the receipt
  log. Path / message fields are preserved.
- :class:`RedactionPolicy`: frozen mapping from tool-name to the tuple of
  arg-fields to redact.
- :func:`bind_and_redact`: signature-aware wrapper that binds positional
  args to parameter names so redaction covers both ``f("path", "secret")``
  and ``f(path="path", content="secret")`` call shapes. Sibling adapters
  used to re-derive the bind-and-redact pattern via inline
  ``_build_redacted_parameters`` / ``_redact_method_call`` /
  ``_task_parameters`` helpers; this consolidates the security-critical
  surface in one place.
- :data:`DEFAULT_TOOL_POSITIONAL_NAMES`: positional-name table for
  chio-default tools. Used by :func:`bind_and_redact` when the wrapped
  callable cannot be introspected (C-extension callable, pure forwarding
  ``def f(*args, **kwargs)``, or ``fn=None``).

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
import inspect
from collections.abc import Callable, Mapping, Sequence
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


# ---------------------------------------------------------------------------
# bind_and_redact
# ---------------------------------------------------------------------------

# Positional-name table for chio-default tools. When the bound callable is
# not introspectable (C extension, pure forwarding wrapper without
# ``__signature__``, or ``None``), :func:`bind_and_redact` falls back to
# this table so it can still map ``positional[0]`` -> ``"path"`` and
# ``positional[1]`` -> ``"content"`` for ``chio_file_write``.
#
# Adapters with custom tools can extend this by passing their own
# ``positional_table`` argument; the in-tree default is intentionally
# minimal so the contract stays narrow.
DEFAULT_TOOL_POSITIONAL_NAMES: Mapping[str, tuple[str, ...]] = {
    "chio_file_write": ("path", "content"),
    "chio_file_edit": ("path", "patch"),
}


def _signature_or_none(fn: Callable[..., Any] | None) -> inspect.Signature | None:
    """Return ``inspect.signature(fn)`` or ``None`` if introspection fails.

    Builtins, many C extensions, and some ``functools.partial`` shapes
    raise :class:`ValueError` (or :class:`TypeError`) when introspected.
    Treat any failure as "not introspectable" so callers fall back to the
    positional-name table.
    """
    if fn is None:
        return None
    try:
        return inspect.signature(fn)
    except (TypeError, ValueError):
        return None


def _is_pure_forwarder(sig: inspect.Signature) -> bool:
    """``True`` iff the signature is exactly ``(*args, **kwargs)``.

    A pure forwarder offers no information about positional names, so
    binding is no better than the positional-name table fallback.
    """
    params = list(sig.parameters.values())
    if len(params) != 2:
        return False
    kinds = {p.kind for p in params}
    return kinds == {
        inspect.Parameter.VAR_POSITIONAL,
        inspect.Parameter.VAR_KEYWORD,
    }


def _drop_first_positional(sig: inspect.Signature) -> inspect.Signature:
    """Return ``sig`` with the first positional-or-keyword param removed.

    Used when ``drop_self=True`` to skip a method receiver regardless of
    whether it is literally named ``self`` (covers ``cls`` on
    classmethods, ``this`` on user-defined receivers, etc.).
    """
    params = list(sig.parameters.values())
    for idx, param in enumerate(params):
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            return sig.replace(parameters=params[:idx] + params[idx + 1 :])
    return sig


def _redact_named(
    parameters: Mapping[str, Any],
    *,
    tool_name: str,
    policy: RedactionPolicy,
) -> dict[str, Any]:
    """Apply ``policy`` to a name-keyed mapping; thin wrapper for clarity."""
    return redact_args(tool_name, parameters, policy=policy)


def bind_and_redact(
    fn: Callable[..., Any] | None,
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    tool_name: str,
    policy: RedactionPolicy | None = None,
    drop_self: bool = False,
    positional_table: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Bind ``args`` + ``kwargs`` to ``fn``'s signature, redact named fields
    per ``policy``, and rebuild the original wire shape.

    Positional values stay positional; keyword values stay keyword.
    Callers can therefore pass the result straight to
    ``ChioClient.evaluate_tool_call(parameters={"args": redacted_args,
    "kwargs": redacted_kwargs})`` without the parameter hash drifting.

    Behaviour matrix:

    - ``fn=None`` or ``fn`` not introspectable (C extensions, callables
      without ``__signature__``): falls back to ``positional_table``
      lookup keyed by ``tool_name``. If the tool is not in the table,
      kwargs are redacted but positional args are forwarded raw.
    - Pure forwarding wrapper (``def f(*args, **kwargs)``): same fallback
      as above; the signature carries no name information.
    - Fixed signature: positional values are bound to their parameter
      names, redaction runs against the named view, and the result is
      rebuilt with positional values back in their slots.
    - ``VAR_POSITIONAL`` extras: extras have no name to redact against,
      so they stay positional and unredacted (documented limitation;
      protected fields should not flow through ``*args``).
    - ``VAR_KEYWORD`` spillover: the spillover dict is re-redacted so
      kwargs-style protected fields are still covered when they land in
      ``**kwargs`` instead of a named parameter.
    - ``drop_self=True``: skips the first positional-only or
      positional-or-keyword parameter regardless of declared name. Use
      for bound methods where the receiver is not literally ``self`` and
      the caller has not already stripped it.
    - Merge conflict (positional name AND kwarg with the same name):
      both positions are redacted independently; the wire shape preserves
      both, and any :class:`TypeError` Python would raise for the
      duplicate is left for the caller to surface (we are not in the
      business of validating arity here).

    Returns:
        ``(redacted_args, redacted_kwargs)`` -- a fresh list and dict that
        callers may mutate freely.
    """
    effective_policy = (
        policy if policy is not None else RedactionPolicy.chio_default()
    )
    table = (
        positional_table
        if positional_table is not None
        else DEFAULT_TOOL_POSITIONAL_NAMES
    )

    sig = _signature_or_none(fn)
    # When drop_self is set we also strip the first positional value from
    # the caller's args before binding; the receiver is restored at the
    # head of the rebuilt positional list so the wire shape is unchanged.
    receiver_value: Any = None
    has_receiver = False
    bind_args: tuple[Any, ...] = tuple(args)
    if sig is not None and drop_self:
        sig = _drop_first_positional(sig)
        if bind_args:
            receiver_value = bind_args[0]
            has_receiver = True
            bind_args = bind_args[1:]

    use_table_fallback = sig is None or _is_pure_forwarder(sig)

    # bind_partial may raise TypeError (e.g. duplicate name across
    # positional + kwargs). When that happens we redact what we can via
    # the positional-name table so positional secrets are still covered;
    # the caller's TypeError will surface naturally when they invoke fn.
    bound: inspect.BoundArguments | None = None
    if not use_table_fallback:
        assert sig is not None
        try:
            bound = sig.bind_partial(*bind_args, **kwargs)
        except TypeError:
            use_table_fallback = True

    if use_table_fallback:
        fb_args, fb_kwargs = _table_fallback_redact(
            bind_args,
            kwargs,
            tool_name=tool_name,
            policy=effective_policy,
            table=table,
        )
        if has_receiver:
            fb_args.insert(0, receiver_value)
        return fb_args, fb_kwargs

    assert sig is not None and bound is not None  # for mypy

    # bound.arguments preserves only the parameter names that were
    # supplied. VAR_KEYWORD spillover lands as a nested dict under the
    # parameter's declared name; VAR_POSITIONAL extras land as a tuple.
    var_keyword_param: str | None = None
    var_positional_param: str | None = None
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            var_keyword_param = param.name
        elif param.kind is inspect.Parameter.VAR_POSITIONAL:
            var_positional_param = param.name

    # Redact named (fixed) params first.
    fixed_named = {
        name: value
        for name, value in bound.arguments.items()
        if name not in (var_keyword_param, var_positional_param)
    }
    redacted_fixed = _redact_named(
        fixed_named, tool_name=tool_name, policy=effective_policy
    )
    # Redact VAR_KEYWORD spillover separately; protected fields that
    # arrived via **kwargs spillover are still covered because the
    # spillover dict shares the same redaction policy.
    redacted_spillover: dict[str, Any] = {}
    if var_keyword_param is not None and var_keyword_param in bound.arguments:
        spilled_in = bound.arguments[var_keyword_param]
        if isinstance(spilled_in, Mapping):
            redacted_spillover = _redact_named(
                spilled_in, tool_name=tool_name, policy=effective_policy
            )

    # Walk the caller's positional list and pull redacted values back
    # into their original wire positions.
    rebuilt_args = []
    positional_param_names: list[str] = [
        p.name
        for p in sig.parameters.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    for idx, value in enumerate(bind_args):
        if idx < len(positional_param_names):
            name = positional_param_names[idx]
            if name in redacted_fixed:
                rebuilt_args.append(redacted_fixed[name])
                continue
        # Extras (VAR_POSITIONAL) have no name, so they stay raw.
        rebuilt_args.append(value)

    rebuilt_kwargs: dict[str, Any] = {}
    for name, value in kwargs.items():
        if name in redacted_fixed:
            rebuilt_kwargs[name] = redacted_fixed[name]
        elif name in redacted_spillover:
            rebuilt_kwargs[name] = redacted_spillover[name]
        else:
            rebuilt_kwargs[name] = value

    if has_receiver:
        rebuilt_args.insert(0, receiver_value)
    return rebuilt_args, rebuilt_kwargs


def _table_fallback_redact(
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    tool_name: str,
    policy: RedactionPolicy,
    table: Mapping[str, tuple[str, ...]],
) -> tuple[list[Any], dict[str, Any]]:
    """Shared positional-name table redaction used by every fallback path."""
    positional_names = table.get(tool_name, ())
    redacted_kwargs = _redact_named(
        kwargs, tool_name=tool_name, policy=policy
    )
    if not positional_names:
        # No name information at all. Forward args raw; kwargs were
        # redacted already.
        return list(args), redacted_kwargs

    named_from_positional: dict[str, Any] = {}
    for idx, value in enumerate(args):
        if idx >= len(positional_names):
            break
        named_from_positional[positional_names[idx]] = value
    redacted_named = _redact_named(
        named_from_positional, tool_name=tool_name, policy=policy
    )
    rebuilt_args: list[Any] = []
    for idx, value in enumerate(args):
        if idx < len(positional_names):
            rebuilt_args.append(redacted_named[positional_names[idx]])
        else:
            # Extras beyond the table entry stay positional and raw.
            rebuilt_args.append(value)
    return rebuilt_args, redacted_kwargs


__all__ = [
    "DEFAULT_TOOL_POSITIONAL_NAMES",
    "RedactArgs",
    "RedactionPolicy",
    "bind_and_redact",
    "redact_args",
]
