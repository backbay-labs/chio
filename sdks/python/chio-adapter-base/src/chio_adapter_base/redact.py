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
  and ``f(path="path", content="secret")`` call shapes. This is the one
  canonical place for the security-critical bind-and-redact surface;
  sibling adapters route their wrapper redaction through it rather than
  reimplementing it inline.
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


def _is_pure_forwarder(
    sig: inspect.Signature,
    *,
    protected_fields: tuple[str, ...] = (),
) -> bool:
    """``True`` iff the signature has no fixed (named) parameters AND no
    VAR_POSITIONAL whose name is itself a protected field.

    Covers ``(*args, **kwargs)``, ``(*args)``-only, ``(**kwargs)``-only,
    and the empty signature ``()``. Any of these carries no positional
    name information, so binding is no better than the positional-name
    table fallback. Even an empty signature is treated as a forwarder so
    we surface the table mapping rather than silently dropping the
    parameters on a duplicate-name TypeError.

    Exception: ``def upload(*payload)`` where ``payload`` is a protected
    field for the current tool. The variadic name carries the wire
    intent, so the signature path runs (not the table fallback) so each
    extra is redacted under that name. Without this, the table fallback
    would map ``args[0]`` to the table's slot 0 (often ``path``) and
    miss the redaction entirely.
    """
    for param in sig.parameters.values():
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return False
        if (
            param.kind is inspect.Parameter.VAR_POSITIONAL
            and param.name in protected_fields
        ):
            return False
    return True


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
    """Apply ``policy`` to a name-keyed mapping."""
    return redact_args(tool_name, parameters, policy=policy)


def build_alias_map(
    sig_positional_names: Sequence[str],
    table_slots: Sequence[str],
    protected_fields: Sequence[str],
    *,
    allow_ambiguous_cycling: bool = True,
) -> dict[str, str]:
    """Map wrapper sig names to canonical names for a per-tool table.

    The two semantic guarantees:

    1. A wrapper-name that itself matches a canonical (either in the
       per-tool table or in the policy's protected fields) routes to
       itself - the wrapper named the slot canonically, no aliasing
       needed (and aliasing would corrupt the wire shape).
    2. For unmatched wrapper-names we use index-based routing onto the
       same-index table slot, EXCEPT when a name-position swap is
       detected (a wrapper-name that IS a canonical but at a different
       index than where it appears in the table). When swap is
       detected, fall back to a "claim canonicals in declaration order
       and route the unmatched wrapper-names to the unclaimed
       canonicals" algorithm. This is the v0.3 index-collision guard.

    ``allow_ambiguous_cycling`` (default ``True``) controls the
    swap-detected fail-closed cycling. When ``True`` (chio-default
    tools), the cycling fires so an extra unmatched wrapper-name still
    redacts under a protected canonical. When ``False`` (custom-policy
    tools that are NOT in :data:`DEFAULT_TOOL_POSITIONAL_NAMES`), the
    cycling is suppressed: unmatched wrapper-names without a free
    canonical stay self-aliased, preserving the "redact only named
    fields" custom-policy contract.

    The ``def write(body, path)`` case routes ``body`` -> ``content``,
    not ``path``: ``path`` is already claimed at idx 1 by the swap-aware
    Pass 1.
    """
    sig_to_canonical: dict[str, str] = {}
    claimed_canonicals: set[str] = set()
    table_slots_set = set(table_slots)
    protected_set = set(protected_fields)

    # Pass 1: self-canonical wrapper-names claim their slots.
    for sig_name in sig_positional_names:
        if sig_name in table_slots_set or sig_name in protected_set:
            sig_to_canonical[sig_name] = sig_name
            claimed_canonicals.add(sig_name)

    # Detect a name-position swap: a wrapper-name that IS a canonical
    # but appears at a different index than where the same name lives
    # in the table_slots. When swap is detected, prefer the
    # "next-unclaimed-protected" routing so the wrapper's NAMING
    # intent (not positional alignment) drives the alias map.
    swap_detected = False
    for idx, sig_name in enumerate(sig_positional_names):
        if sig_name in table_slots_set:
            try:
                table_idx = table_slots.index(sig_name)
            except ValueError:
                continue
            if table_idx != idx:
                swap_detected = True
                break

    # Pass 2: route unmatched wrapper-names.
    #
    # Pre-compute the swap-detected ambiguity check: when the swap-aware
    # branch is in play and there are MORE unmatched wrapper-names than
    # unclaimed protected canonicals, any of the wrappers could carry
    # the secret. Fail-closed by cycling through the protected list so
    # every unmatched wrapper-name redacts to a protected canonical
    # (mirrors the kwonly Pass B ambiguous-fail-closed semantics in
    # ``bind_and_redact``). Example:
    # ``def write_file(label, body, path)`` greedily gave the only
    # protected slot to ``label`` and left the secret in ``body`` raw.
    swap_unclaimed_wrappers: list[str] = []
    swap_unclaimed_canonicals: list[str] = []
    swap_ambiguous = False
    if swap_detected:
        swap_unclaimed_wrappers = [
            sn for sn in sig_positional_names if sn not in sig_to_canonical
        ]
        swap_unclaimed_canonicals = [
            c for c in protected_fields if c not in claimed_canonicals
        ]
        swap_ambiguous = (
            len(swap_unclaimed_wrappers) > len(swap_unclaimed_canonicals)
            and len(protected_fields) > 0
            and allow_ambiguous_cycling
        )
    swap_cycle = list(protected_fields)
    swap_cycle_idx = 0

    for idx, sig_name in enumerate(sig_positional_names):
        if sig_name in sig_to_canonical:
            continue
        if not swap_detected:
            # No swap: index-based routing (backward compat with the
            # v0.2 behaviour). If the same-index table slot is
            # protected and unclaimed, route the wrapper-name onto it
            # (so ``def my_writer(p, b)`` for chio_file_write maps b
            # at idx 1 to ``content``). Otherwise leave the
            # wrapper-name as-is.
            if idx < len(table_slots):
                same_index_slot = table_slots[idx]
                if (
                    same_index_slot in protected_set
                    and same_index_slot not in claimed_canonicals
                ):
                    sig_to_canonical[sig_name] = same_index_slot
                    claimed_canonicals.add(same_index_slot)
                    continue
            sig_to_canonical[sig_name] = sig_name
            continue
        # Swap-detected branch: route by next-unclaimed-protected. When
        # ambiguous (more unmatched wrappers than free canonicals),
        # fail-closed by cycling through the protected list so every
        # unmatched wrapper-name aliases to a protected canonical.
        if swap_ambiguous:
            sig_to_canonical[sig_name] = swap_cycle[
                swap_cycle_idx % len(swap_cycle)
            ]
            swap_cycle_idx += 1
            continue
        nxt = next(
            (c for c in protected_fields if c not in claimed_canonicals),
            None,
        )
        if nxt is not None:
            sig_to_canonical[sig_name] = nxt
            claimed_canonicals.add(nxt)
        else:
            sig_to_canonical[sig_name] = sig_name

    return sig_to_canonical


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
    - ``VAR_POSITIONAL`` extras: extras have no fixed parameter name,
      but the per-tool ``positional_table`` (the chio default or a
      caller-supplied override) still declares names for each wire-level
      slot. Each extra is matched against the next free table slot (one
      not already filled by a bound fixed positional or kwarg) and
      redacted under that slot's name. Values stay positional in the
      rebuilt ``args`` so the function's call site is unchanged; only
      the redacted *values* differ.
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
    # Ambiguous-fail-closed cycling (kwonly Pass B + build_alias_map
    # swap-ambiguous branch) is gated to chio-default tools only. For
    # those tools we know the canonical slot names with high confidence
    # and can safely over-redact ambiguous extra wrappers. For custom
    # tools (not in the in-tree default table) the user's RedactionPolicy
    # is the source of truth for which fields are sensitive; redacting
    # extra fields beyond ``policy.body_fields[tool_name]`` would break
    # the custom-policy "redact only named fields" contract.
    allow_ambiguous_cycling = tool_name in DEFAULT_TOOL_POSITIONAL_NAMES

    sig = _signature_or_none(fn)
    # When drop_self is set we also strip the first positional value from
    # the caller's args before binding; the receiver is restored at the
    # head of the rebuilt positional list so the wire shape is unchanged.
    # The same stripping happens on the signature-unavailable / pure
    # forwarder path: without it, an actor method's receiver would slot
    # into ``positional[0]`` and shift every named-positional binding by
    # one (e.g. the receiver becomes ``"path"`` and the real path becomes
    # the unredacted ``"content"``).
    receiver_value: Any = None
    has_receiver = False
    bind_args: tuple[Any, ...] = tuple(args)
    if drop_self and bind_args:
        if sig is not None:
            sig = _drop_first_positional(sig)
        receiver_value = bind_args[0]
        has_receiver = True
        bind_args = bind_args[1:]

    # Protected fields for this tool (canonical names declared by the
    # policy). Pass into the forwarder check so variadic-only signatures
    # whose ``*name`` is a protected field still take the signature path
    # (and therefore the named-variadic redaction).
    protected_fields_for_tool_pre: tuple[str, ...] = (
        effective_policy.body_fields.get(tool_name) or ()
    )
    use_table_fallback = sig is None or _is_pure_forwarder(
        sig, protected_fields=protected_fields_for_tool_pre
    )
    # When True, the table is the ONLY source of positional ordering
    # (pure forwarder / non-introspectable / fn=None). Positional args
    # consume table slots not already filled by kwargs. When False, the
    # signature already pinned positional values to slot indices, so
    # positional[idx] -> slot[idx] directly (merge-conflict TypeError
    # path).
    fallback_skips_kwarg_filled_slots = use_table_fallback

    # bind_partial may raise TypeError (e.g. duplicate name across
    # positional + kwargs for a fixed-signature custom tool). When that
    # happens we still want to redact positional secrets, but the
    # caller-supplied / chio-default ``positional_table`` may not list
    # the custom tool. Derive a positional-name table from the
    # signature itself so the merge-conflict fallback covers
    # custom-tool fixed signatures too.
    bound: inspect.BoundArguments | None = None
    fallback_table: Mapping[str, tuple[str, ...]] = table
    fallback_kwarg_alias: Mapping[str, str] | None = None
    if not use_table_fallback:
        assert sig is not None
        try:
            bound = sig.bind_partial(*bind_args, **kwargs)
        except TypeError:
            use_table_fallback = True
            # Stay in the fixed-signature semantics: positional[idx]
            # maps to slot[idx]. Do not skip kwarg-filled slots.
            fallback_skips_kwarg_filled_slots = False
            sig_positional_names = tuple(
                p.name
                for p in sig.parameters.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            )
            # Fail-closed extension for overflow positional values that
            # have nowhere to land. The wrapped fn's bind_partial raised,
            # so the caller's positional values are arity-invalid. Two
            # shapes are silent-leak risks if we stop at
            # sig_positional_names alone:
            #
            #   (a) ``def write(path, *, content)`` invoked as
            #       ``write('/tmp/x', 'PROD_SECRET')`` -- bind_partial
            #       raises (``content`` is keyword-only); the second
            #       positional has no fixed slot and would be forwarded
            #       raw. Extend the slot list with kwonly names whose
            #       canonical IS protected so the overflow positional
            #       redacts under the protected canonical.
            #
            #   (b) ``def write_file(*content)`` invoked as
            #       ``write_file('PROD_SECRET', path='/tmp/x')`` -- the
            #       protected-named variadic guard sends this through the
            #       signature path, but bind_partial raises on the unknown
            #       ``path`` kwarg. The fallback's table-derived slot list
            #       is empty, so the chio-default ``("path", "content")``
            #       runs and routes the secret to the unprotected ``path``
            #       slot. Use the variadic name itself as the slot when it
            #       is a protected canonical so the secret redacts.
            kwonly_protected_slots: list[tuple[str, str]] = []
            kwonly_protected_set: set[str] = set()
            for p in sig.parameters.values():
                if p.kind is not inspect.Parameter.KEYWORD_ONLY:
                    continue
                if p.name in sig_positional_names:
                    continue
                if p.name in kwonly_protected_set:
                    continue
                if (
                    p.name in protected_fields_for_tool_pre
                    or p.name in table.get(tool_name, ())
                ):
                    kwonly_protected_slots.append((p.name, p.name))
                    kwonly_protected_set.add(p.name)
                    continue
                # Wrapper alias for a protected canonical - route by
                # next-unclaimed (mirrors build_alias_map semantics).
                claimed_so_far = set(sig_positional_names) | kwonly_protected_set
                nxt = next(
                    (
                        c
                        for c in protected_fields_for_tool_pre
                        if c not in claimed_so_far
                    ),
                    None,
                )
                if nxt is not None:
                    kwonly_protected_slots.append((p.name, nxt))
                    kwonly_protected_set.add(p.name)

            var_positional_protected_slot: str | None = None
            has_var_positional = False
            for p in sig.parameters.values():
                if p.kind is inspect.Parameter.VAR_POSITIONAL:
                    has_var_positional = True
                if (
                    p.kind is inspect.Parameter.VAR_POSITIONAL
                    and p.name in protected_fields_for_tool_pre
                ):
                    var_positional_protected_slot = p.name
                    break

            extended_positional_list = list(sig_positional_names)
            table_slots_for_tool_pre = tuple(table.get(tool_name, ()))
            for kwonly_name, canonical_name in kwonly_protected_slots:
                # If a keyword-only protected alias is being used as the
                # overflow target, preserve any earlier canonical table
                # slots before appending the kwonly name. This keeps
                # kwonly-only wrappers such as ``def write_file(*, body)``
                # aligned as ``path, body`` rather than ``body`` so an
                # invalid positional call redacts only the body-like slot.
                if canonical_name in table_slots_for_tool_pre:
                    canonical_idx = table_slots_for_tool_pre.index(
                        canonical_name
                    )
                    while len(extended_positional_list) < canonical_idx:
                        extended_positional_list.append(
                            table_slots_for_tool_pre[
                                len(extended_positional_list)
                            ]
                        )
                extended_positional_list.append(kwonly_name)
            extended_positional_names = tuple(extended_positional_list)
            if var_positional_protected_slot is not None:
                # Pad the slot list with the variadic name so each overflow
                # positional past sig_positional_names redacts under it.
                # Use the actual positional cardinality so multi-chunk
                # variadic inputs all redact.
                pad_count = max(
                    1,
                    len(bind_args) - len(extended_positional_names),
                )
                extended_positional_names = extended_positional_names + (
                    var_positional_protected_slot,
                ) * pad_count

            if (
                not has_var_positional
                and allow_ambiguous_cycling
                and protected_fields_for_tool_pre
                and extended_positional_names
                and len(bind_args) > len(extended_positional_names)
            ):
                base_alias = build_alias_map(
                    extended_positional_names,
                    table.get(tool_name, ()),
                    protected_fields_for_tool_pre,
                    allow_ambiguous_cycling=allow_ambiguous_cycling,
                )
                overflow_slot = next(
                    (
                        slot
                        for slot in reversed(extended_positional_names)
                        if base_alias.get(slot, slot)
                        in protected_fields_for_tool_pre
                    ),
                    protected_fields_for_tool_pre[0],
                )
                overflow_count = len(bind_args) - len(extended_positional_names)
                extended_positional_names = extended_positional_names + (
                    overflow_slot,
                ) * overflow_count

            if extended_positional_names:
                # Signature-derived names take precedence so wrappers that
                # rename a protected field (e.g. `def write(content, path)`
                # vs the chio-default `("path", "content")`) redact at the
                # right slot. Caller-supplied table entries for OTHER tools
                # still pass through; only the chio-default entry for this
                # tool gets shadowed by the wrapper's actual param order.
                fallback_table = {
                    **table,
                    tool_name: extended_positional_names,
                }
            # Build a wrapper-name -> canonical alias map keyed off the
            # SAME index-aware routing the non-fallback path uses, so
            # kwargs supplied under a wrapper-renamed alias (e.g.
            # ``body=`` for a tool whose protected canonical is
            # ``content``) still redact correctly even when bind_partial
            # blew up. Without this, a TypeError-fallback for a renamed
            # signature would only redact kwargs whose name literally
            # appears in the policy's body_fields.
            #
            # Build the alias map by routing non-canonical wrapper-names
            # to unclaimed protected canonicals - mirrors the algorithm
            # used on the non-fallback path so both paths share semantic
            # behaviour. "Canonical" here is the table from the
            # CALLER-or-default ``positional_table`` for this tool (NOT
            # the signature-derived fallback_table, which by definition
            # uses wrapper names): a wrapper-name is "canonical" if it
            # appears in that table for this tool.
            # Mirror the alias-map algorithm used on the non-fallback
            # path so semantics match. Use the CALLER-or-default table
            # for the canonical lookup (NOT the signature-derived
            # fallback_table; that table by definition uses wrapper
            # names).
            _alias_fb = build_alias_map(
                extended_positional_names,
                table.get(tool_name, ()),
                protected_fields_for_tool_pre,
                allow_ambiguous_cycling=allow_ambiguous_cycling,
            )
            # Walk kwonly names too: any kwonly that did not get an
            # alias from the positional pass routes to the next unclaimed
            # protected canonical. Apply the same ambiguous-fail-closed
            # semantics the non-fallback kwonly Pass B uses. Example:
            # ``def write_file(path, *, label, body)`` called with extra
            # positional + body kwarg leaked because the greedy
            # build_alias_map run gave the only canonical to ``label``
            # while ``body`` stayed self-aliased.
            kwonly_names_fb = tuple(
                p.name
                for p in sig.parameters.values()
                if p.kind is inspect.Parameter.KEYWORD_ONLY
            )
            # Drop any greedy aliases build_alias_map handed to
            # KWONLY-derived slot names so the dedicated kwonly logic
            # owns their routing (mirrors non-fallback Pass A/B
            # ownership). Self-canonical kwonlys (name itself in table
            # OR protected) are preserved as self-aliases.
            self_canonical_fb_kwonlys: list[str] = []
            for sn in kwonly_names_fb:
                if (
                    sn in table.get(tool_name, ())
                    or sn in protected_fields_for_tool_pre
                ):
                    self_canonical_fb_kwonlys.append(sn)
                    _alias_fb[sn] = sn
                elif sn in _alias_fb:
                    # Wrapper alias kwonly: discard the greedy mapping
                    # so the ambiguity check below decides where it
                    # routes.
                    _alias_fb.pop(sn, None)
            already_canonical_protected_fb: set[str] = {
                canonical
                for canonical in _alias_fb.values()
                if canonical in protected_fields_for_tool_pre
            }
            unclaimed_kwonlys_fb: list[str] = [
                sn
                for sn in kwonly_names_fb
                if sn not in self_canonical_fb_kwonlys
                and sn not in _alias_fb
            ]
            unclaimed_canonicals_fb: list[str] = [
                canonical
                for canonical in protected_fields_for_tool_pre
                if canonical not in already_canonical_protected_fb
            ]
            if unclaimed_kwonlys_fb and len(unclaimed_kwonlys_fb) <= len(
                unclaimed_canonicals_fb
            ):
                # Unambiguous: 1:1 (or surjective) mapping exists.
                # Greedy declaration-order routing.
                for sn in unclaimed_kwonlys_fb:
                    for canonical in unclaimed_canonicals_fb:
                        if canonical in already_canonical_protected_fb:
                            continue
                        _alias_fb[sn] = canonical
                        already_canonical_protected_fb.add(canonical)
                        break
            elif (
                unclaimed_kwonlys_fb
                and protected_fields_for_tool_pre
                and allow_ambiguous_cycling
            ):
                # Ambiguous: more kwonly aliases than free canonicals.
                # Fail-closed by cycling each unclaimed kwonly through
                # the protected list. Gated to chio-default tools only;
                # custom-policy tools fall through to the self-alias
                # branch below so only explicitly-named fields redact.
                cycle_fb = list(protected_fields_for_tool_pre)
                for i, sn in enumerate(unclaimed_kwonlys_fb):
                    _alias_fb[sn] = cycle_fb[i % len(cycle_fb)]
            else:
                # No protected canonicals at all (or custom-policy tool
                # with ambiguous cycling suppressed). Leave unclaimed
                # kwonlys as self-aliases so they pass through raw and
                # only their literal-named protected siblings redact.
                for sn in unclaimed_kwonlys_fb:
                    _alias_fb[sn] = sn
            fallback_kwarg_alias = _alias_fb

    if use_table_fallback:
        fb_args, fb_kwargs = _table_fallback_redact(
            bind_args,
            kwargs,
            tool_name=tool_name,
            policy=effective_policy,
            table=fallback_table,
            skip_kwarg_filled_slots=fallback_skips_kwarg_filled_slots,
            kwarg_alias_map=fallback_kwarg_alias,
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

    # The wrapper's signature param names are the wrapper's own naming
    # (e.g. ``def write_file(path, body)``) which may differ from the
    # canonical wire-level slot names declared by the per-tool
    # ``positional_table`` (e.g. ``("path", "content")`` for
    # ``chio_file_write``). The redaction policy's protected fields are
    # keyed by canonical names. To redact correctly when the wrapper
    # uses an alias, build a canonical-named view of fixed params and
    # remember the alias mapping so the rebuild can look values up by
    # canonical name and emit them under the wrapper's name.
    #
    # Aliasing is only applied when the wrapper's param name does NOT
    # itself appear in the table. A param whose name already matches a
    # canonical slot is left alone - the wrapper is naming things
    # canonically (possibly in a non-default order) and we redact by
    # name. This guards against false aliasing for shapes like
    # ``def write(content, /, **kw)`` where the wrapper's param IS the
    # canonical name but happens to sit at a different position than
    # the table's default ordering.
    table_slots_for_tool: tuple[str, ...] = table.get(tool_name, ())
    fixed_positional_names: list[str] = [
        p.name
        for p in sig.parameters.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    # Build alias map by ROUTING to protected canonical names, not by
    # same-index table-slot lookup.
    #
    # Aliasing a non-canonical wrapper-name at index N to
    # ``table_slots_for_tool[N]`` regardless of whether that slot is
    # itself protected breaks ``def write(body, path)`` for
    # chio_file_write whose table is ``("path", "content")``: ``body``
    # would be aliased to ``path`` (idx 0), but ``path`` is NOT a
    # protected field; the redactor would never look it up and
    # ``content`` would never get its alias either. The correct binding
    # is ``body`` -> ``content`` (the unclaimed protected canonical).
    #
    # Algorithm:
    #   1. Pass 1 - any wrapper-name that already matches a canonical
    #      slot (whether or not the slot is itself protected) is mapped
    #      to itself. These slots become "claimed" by the wrapper.
    #   2. Pass 2 - for every remaining wrapper-name, route to the
    #      next unclaimed protected canonical (one of
    #      ``policy.body_fields[tool_name]`` not yet used as an alias
    #      target). If no protected canonical is free, leave the name
    #      as-is.
    #
    # The wrapper's positional ORDER is preserved (Pass 2 walks the
    # remaining names in declaration order and routes to protected
    # canonicals in their declared order). For the common one-protected
    # case (chio_file_write has a single protected field ``content``)
    # the only remaining wrapper-name binds to it; for tools with
    # multiple protected fields the ordering still gives a stable map.
    protected_fields_for_tool: tuple[str, ...] = (
        effective_policy.body_fields.get(tool_name) or ()
    )
    sig_to_canonical: dict[str, str] = build_alias_map(
        fixed_positional_names,
        table_slots_for_tool,
        protected_fields_for_tool,
        allow_ambiguous_cycling=allow_ambiguous_cycling,
    )

    # Also walk KEYWORD_ONLY params: TaskFlow / decorator wrappers shaped
    # like ``def write_file(path, *, body)`` keep the protected body in a
    # keyword-only slot. Without this, a kwarg call such as
    # ``write_file('/tmp/x', body='PROD_SECRET')`` would never map ``body``
    # to the canonical ``content`` slot and the raw secret would be
    # forwarded under ``parameters['kwargs']['body']``. Match each
    # keyword-only param against the protected fields for this tool: if
    # the param's name is already canonical we leave it; otherwise we
    # alias it to the first protected field that has not yet been claimed
    # by a fixed positional or another keyword-only param.
    #
    # The kwonly aliasing pass is intentionally narrow. A VAR_POSITIONAL
    # parameter that ITSELF names a protected canonical (e.g.
    # ``def writer(*content, path)`` for chio_file_write) carries the
    # body positionally, so the kwonly slot is not the body and aliasing
    # would mis-route. When the VAR_POSITIONAL is unrelated (e.g.
    # ``def writer(path, *rest, body)`` where ``*rest`` is just overflow),
    # the kwonly may still be the body alias and the kwonly aliasing
    # pass MUST run; otherwise a kwarg call like ``writer('/tmp/x',
    # body='PROD_SECRET')`` forwards the secret raw.
    # Only a variadic parameter whose name is an actual PROTECTED
    # canonical suppresses kwonly aliasing. Firing the guard whenever
    # ``*name`` matches any table slot (protected or not) over-broadly
    # skips aliasing for shapes like ``def write_file(*path, body)``:
    # ``path`` is in the chio ``("path", "content")`` table but is NOT a
    # protected field, so the kwonly ``body`` must still alias to
    # ``content`` rather than forward raw.
    var_positional_is_protected_canonical = any(
        p.kind is inspect.Parameter.VAR_POSITIONAL
        and p.name in protected_fields_for_tool
        for p in sig.parameters.values()
    )
    if protected_fields_for_tool and not var_positional_is_protected_canonical:
        already_canonical_protected: set[str] = {
            canonical
            for canonical in sig_to_canonical.values()
            if canonical in protected_fields_for_tool
        }
        # Pass A: every kwonly that is itself canonical (in the table
        # OR matches a protected field name directly) is "self-
        # canonical" and claims its slot. This guards against false
        # aliasing for shapes like ``def fn(*, body)`` where the
        # wrapper IS naming the canonical body field; aliasing would
        # be a no-op. It also covers ``def fn(*, label, body)`` for a
        # custom-policy tool where ``body`` IS the protected
        # canonical: leaving label unaliased and body self-canonical.
        kwonly_params = [
            p
            for p in sig.parameters.values()
            if p.kind is inspect.Parameter.KEYWORD_ONLY
        ]
        for param in kwonly_params:
            kw_name = param.name
            if (
                kw_name in table_slots_for_tool
                or kw_name in protected_fields_for_tool
            ):
                sig_to_canonical[kw_name] = kw_name
                if kw_name in protected_fields_for_tool:
                    already_canonical_protected.add(kw_name)
        # Pass B: any remaining kwonly is a wrapper alias for a
        # protected field. Bind to the first unclaimed protected
        # canonical. When more unaliased kwonlys remain than there are
        # unclaimed protected canonicals, fail-closed: alias EVERY
        # remaining kwonly to a protected canonical (cycling through
        # the protected list) so the secret is redacted regardless of
        # which kwonly carries it. Mirrors the merge-conflict semantics
        # used elsewhere in this module: when ambiguous, redact more.
        # Example: ``def fn(path, *, label, body)`` greedily gave the
        # only protected slot to the first-declared kwonly ``label`` and
        # left the secret in ``body`` raw.
        unclaimed_kwonlys: list[str] = [
            param.name
            for param in kwonly_params
            if param.name not in sig_to_canonical
        ]
        unclaimed_canonicals: list[str] = [
            canonical
            for canonical in protected_fields_for_tool
            if canonical not in already_canonical_protected
        ]
        if unclaimed_kwonlys and len(unclaimed_kwonlys) <= len(
            unclaimed_canonicals
        ):
            # Unambiguous: a 1:1 (or surjective into canonicals) mapping
            # exists. Greedy declaration-order routing is safe here.
            for kw_name in unclaimed_kwonlys:
                for canonical in unclaimed_canonicals:
                    if canonical in already_canonical_protected:
                        continue
                    sig_to_canonical[kw_name] = canonical
                    already_canonical_protected.add(canonical)
                    break
        elif (
            unclaimed_kwonlys
            and protected_fields_for_tool
            and allow_ambiguous_cycling
        ):
            # Ambiguous: more kwonly aliases than free canonicals. Any
            # of them could carry the secret. Fail-closed by routing
            # each to a protected canonical (cycling so every kwonly
            # gets redacted). Independent merge-conflict redaction
            # downstream keeps the wire shape so callers see one stub
            # per kwarg.
            #
            # Gated to chio-default tools only: for custom-policy tools
            # (not in DEFAULT_TOOL_POSITIONAL_NAMES) the user has
            # explicitly named which fields to redact, so the cycling
            # over-redacts and breaks the custom-policy contract. Such
            # tools fall through to the no-op below: unclaimed kwonlys
            # stay self-aliased and only the explicitly-named protected
            # fields get redacted.
            cycle = list(protected_fields_for_tool)
            for i, kw_name in enumerate(unclaimed_kwonlys):
                sig_to_canonical[kw_name] = cycle[i % len(cycle)]

    # Redact named (fixed) params first. Build the dict using canonical
    # names so the policy lookup matches the wire-level contract even
    # when the wrapper renamed the param.
    fixed_named: dict[str, Any] = {}
    # Track positional-arg collisions: two or more fixed params routed
    # to the same protected canonical (e.g. swap-detected ambiguous case
    # where ``def write_file(label, body, path)`` aliases both ``label``
    # and ``body`` to ``content``). When this happens, ``fixed_named``
    # collapses both values to one slot and the redacted byte_count is
    # whichever wrote last. The rebuild below redacts each colliding
    # positional INDEPENDENTLY so each stub reflects its own value's
    # byte_count (mirrors the kwarg-collision logic further down).
    canonical_arg_counts: dict[str, int] = {}
    for name in bound.arguments:
        if name in (var_keyword_param, var_positional_param):
            continue
        canonical_name = sig_to_canonical.get(name, name)
        canonical_arg_counts[canonical_name] = (
            canonical_arg_counts.get(canonical_name, 0) + 1
        )
    for name, value in bound.arguments.items():
        if name in (var_keyword_param, var_positional_param):
            continue
        canonical_name = sig_to_canonical.get(name, name)
        fixed_named[canonical_name] = value
    redacted_fixed = _redact_named(
        fixed_named, tool_name=tool_name, policy=effective_policy
    )
    # If the VAR_POSITIONAL parameter's NAME matches a protected field
    # in the policy table for this tool, treat every value in the
    # tuple as that protected slot and redact each independently.
    # This covers wrappers like ``def write_file(*content, path)``
    # where ``*content`` is itself the protected field name.
    redacted_var_positional_by_name: tuple[Any, ...] | None = None
    if (
        var_positional_param is not None
        and var_positional_param in protected_fields_for_tool
        and var_positional_param in bound.arguments
    ):
        spilled_var_positional = bound.arguments[var_positional_param]
        if isinstance(spilled_var_positional, tuple):
            redacted_var_positional_by_name = tuple(
                _redact_named(
                    {var_positional_param: value},
                    tool_name=tool_name,
                    policy=effective_policy,
                )[var_positional_param]
                for value in spilled_var_positional
            )
    # Redact VAR_KEYWORD spillover separately; protected fields that
    # arrived via **kwargs spillover are still covered because the
    # spillover dict shares the same redaction policy.
    redacted_spillover: dict[str, Any] = {}
    spillover_keys: set[str] = set()
    if var_keyword_param is not None and var_keyword_param in bound.arguments:
        spilled_in = bound.arguments[var_keyword_param]
        if isinstance(spilled_in, Mapping):
            spillover_keys = set(spilled_in.keys())
            redacted_spillover = _redact_named(
                spilled_in, tool_name=tool_name, policy=effective_policy
            )

    # Walk the caller's positional list and pull redacted values back
    # into their original wire positions.
    rebuilt_args = []
    # ``fixed_positional_names`` (the wrapper's signature names) was
    # already collected above for the canonical alias map. Reuse it.
    # VAR_POSITIONAL extras have no fixed parameter name, but the
    # per-tool positional_table still declares wire-level slot names.
    # Match each extra against the next free table slot (one not
    # already filled by a bound fixed positional or kwarg) so a call
    # like ``fn("/tmp/x", "SECRET")`` against ``def fn(path, *rest)``
    # redacts ``rest[0]`` as ``content`` for chio_file_write.
    table_slots: tuple[str, ...] = table_slots_for_tool
    filled_slot_names: set[str] = set()
    # Slots filled by a fixed positional binding (NOT kwarg). Extras
    # past the fixed cardinality should NOT overflow into these because
    # the fixed binding already consumed the slot for redaction; they
    # surface raw (documented limitation - extras past the fixed
    # cardinality have no name when no free slot exists).
    fixed_positional_filled_slots: set[str] = set()
    for idx in range(min(len(fixed_positional_names), len(bind_args))):
        if idx < len(table_slots):
            filled_slot_names.add(table_slots[idx])
            fixed_positional_filled_slots.add(table_slots[idx])
    # Slots filled ONLY by kwarg (eligible for overflow merge-conflict
    # redaction of VAR_POSITIONAL extras).
    kwarg_filled_slots: set[str] = set()
    # Also account for any kwarg whose wrapper-name aliases a table
    # slot via the canonical map (so ``body=`` for a ``("path","content")``
    # tool fills the ``content`` slot just like ``content=`` would).
    for kwarg_name in kwargs:
        if kwarg_name in table_slots:
            filled_slot_names.add(kwarg_name)
            kwarg_filled_slots.add(kwarg_name)
        canonical_kw = sig_to_canonical.get(kwarg_name)
        if canonical_kw is not None and canonical_kw in table_slots:
            filled_slot_names.add(canonical_kw)
            kwarg_filled_slots.add(canonical_kw)
    free_slot_iter = iter(
        slot for slot in table_slots if slot not in filled_slot_names
    )
    var_positional_extras: dict[int, Any] = {}
    if var_positional_param is not None and table_slots:
        fixed_positional_cardinality = len(fixed_positional_names)
        # Once free table slots are exhausted, fall back onto the
        # PROTECTED canonical slots that were filled by a KWARG (not by
        # a fixed positional binding). The merge-conflict semantics
        # apply: redact the positional and the kwarg independently.
        # This is the VAR_POSITIONAL counterpart of the pure-forwarder
        # overflow path (``def fn(path, *rest, **kw)`` called with
        # ``("/tmp/x", "PROD_SECRET")`` and ``content=KW_SECRET``
        # must redact rest[0] independently).
        # Slots filled by a fixed positional binding already had
        # redaction applied at the fixed-positional path; extras stay
        # raw (preserving the "extras past the table stay raw"
        # contract).
        overflow_protected_slots = [
            slot
            for slot in table_slots
            if slot in kwarg_filled_slots
            and slot not in fixed_positional_filled_slots
            and slot in protected_fields_for_tool
        ]
        overflow_iter = iter(overflow_protected_slots)
        for idx, value in enumerate(bind_args):
            if idx < fixed_positional_cardinality:
                continue
            slot_name = next(free_slot_iter, None)
            if slot_name is None:
                slot_name = next(overflow_iter, None)
                if slot_name is None:
                    break
            redacted_extra = _redact_named(
                {slot_name: value},
                tool_name=tool_name,
                policy=effective_policy,
            )
            var_positional_extras[idx] = redacted_extra[slot_name]

    # Track how many VAR_POSITIONAL values we have already consumed
    # from ``redacted_var_positional_by_name``; the same tuple is used
    # for every position past the fixed-positional cardinality.
    var_pos_named_idx = 0
    for idx, value in enumerate(bind_args):
        if idx < len(fixed_positional_names):
            sig_name = fixed_positional_names[idx]
            # Look up the redacted value via the canonical name (which
            # is the table slot name when one exists, else the sig
            # name itself). This routes alias-renamed slots like
            # ``body`` -> ``content`` to the correct redaction.
            canonical_name = sig_to_canonical.get(sig_name, sig_name)
            if (
                canonical_name in protected_fields_for_tool
                and canonical_arg_counts.get(canonical_name, 0) > 1
            ):
                # Multiple fixed positionals share this canonical:
                # redact each value independently so each stub
                # reflects its own byte_count.
                single_redacted = _redact_named(
                    {canonical_name: value},
                    tool_name=tool_name,
                    policy=effective_policy,
                )
                rebuilt_args.append(single_redacted[canonical_name])
                continue
            if canonical_name in redacted_fixed:
                rebuilt_args.append(redacted_fixed[canonical_name])
                continue
        else:
            # Past the fixed positional cardinality: this is a
            # VAR_POSITIONAL extra. Prefer the named-variadic
            # redaction (when ``*name`` is itself a protected field)
            # over the table-derived slot mapping.
            if (
                redacted_var_positional_by_name is not None
                and var_pos_named_idx
                < len(redacted_var_positional_by_name)
            ):
                rebuilt_args.append(
                    redacted_var_positional_by_name[var_pos_named_idx]
                )
                var_pos_named_idx += 1
                continue
            if idx in var_positional_extras:
                rebuilt_args.append(var_positional_extras[idx])
                continue
        # Extras with no matching free table slot stay raw.
        rebuilt_args.append(value)

    # Detect kwargs that share a canonical alias (the fail-closed
    # ambiguous-kwonly case). When two or more kwargs route to the same
    # canonical, the single ``fixed_named[canonical]`` slot holds only
    # the last-written value, so the shared canonical's stub would
    # report the wrong byte_count for every other aliased kwarg. Mirror
    # the merge-conflict semantics from ``_table_fallback_redact``:
    # redact each colliding kwarg's value INDEPENDENTLY under the
    # canonical so each kwarg's stub reflects its own byte_count.
    # Example: ``def fn(path, *, label, body)`` with both kwargs passed.
    canonical_kw_counts: dict[str, int] = {}
    for kwarg_name in kwargs:
        canonical = sig_to_canonical.get(kwarg_name, kwarg_name)
        if canonical in protected_fields_for_tool:
            canonical_kw_counts[canonical] = (
                canonical_kw_counts.get(canonical, 0) + 1
            )
    rebuilt_kwargs: dict[str, Any] = {}
    for name, value in kwargs.items():
        # When a kwarg landed in VAR_KEYWORD spillover (because the
        # same name is consumed by a positional-only fixed param),
        # the spillover redaction is the correct value for the
        # rebuilt kwargs slot. Without this guard, the
        # ``redacted_fixed`` check below would substitute the
        # positional-only value into the kwarg position and the
        # caller's original spillover value would be silently
        # dropped.
        if name in spillover_keys and name in redacted_spillover:
            rebuilt_kwargs[name] = redacted_spillover[name]
            continue
        # Resolve through the canonical alias map so a kwarg supplied
        # under the wrapper's renamed param (e.g. ``body=`` for a tool
        # whose canonical slot is ``content``) still picks up the
        # redacted value.
        canonical_kw = sig_to_canonical.get(name, name)
        if (
            canonical_kw in protected_fields_for_tool
            and canonical_kw_counts.get(canonical_kw, 0) > 1
        ):
            # Multiple kwargs share this canonical: redact each value
            # independently so each kwarg's stub reflects its own
            # byte_count (fail-closed merge-conflict semantics).
            single_redacted = _redact_named(
                {canonical_kw: value},
                tool_name=tool_name,
                policy=effective_policy,
            )
            rebuilt_kwargs[name] = single_redacted[canonical_kw]
        elif canonical_kw in redacted_fixed:
            rebuilt_kwargs[name] = redacted_fixed[canonical_kw]
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
    skip_kwarg_filled_slots: bool = False,
    kwarg_alias_map: Mapping[str, str] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Shared positional-name table redaction used by every fallback path.

    ``skip_kwarg_filled_slots`` controls how positional args are mapped
    onto table slots when a kwarg has already named one of those slots:

    - ``False`` (default, fixed-signature TypeError fallback): map
      positional[idx] to slot[idx] directly. The fixed signature
      already pinned each positional value to a parameter index, so
      a duplicate-name TypeError is the merge-conflict case where both
      positions get redacted independently.
    - ``True`` (pure forwarder + ``fn=None`` fallback): the table is
      the only source of positional ordering. Skip slots already filled
      by a kwarg of the same name and consume free slots in order. This
      is what ``def proxy(*args, **kwargs)`` called as
      ``proxy("PROD_SECRET", path="/tmp/x")`` needs - the positional
      value is the ``content`` slot, not the already-consumed ``path``
      slot.

    ``kwarg_alias_map`` carries wrapper-name -> canonical-name routing
    derived from the failed bind's signature. When set, kwarg redaction
    runs against canonical names so a wrapper alias such as ``body=``
    on a tool whose protected slot is ``content`` still redacts. Without
    the alias map, a TypeError fallback for a renamed signature would
    only redact kwargs whose name literally matches a policy field.
    """
    positional_names = table.get(tool_name, ())
    # Resolve a wrapper-name -> canonical-name mapping. Without an alias
    # map, names are their own canonical (the table is already
    # canonical). With an alias map, wrapper-renamed slots redact via
    # the canonical name and re-emit under the wrapper name.
    def _to_canonical(name: str) -> str:
        if kwarg_alias_map is None:
            return name
        return kwarg_alias_map.get(name, name)

    if kwarg_alias_map:
        # Redact each kwarg under its canonical name so wrapper aliases
        # still match the policy keys, then re-emit results under the
        # wrapper name so the wire shape stays identical.
        #
        # Two kwargs may resolve to the SAME canonical (e.g. wrapper
        # alias ``body`` -> canonical ``content`` AND a literal
        # ``content=`` kwarg both arriving in the same call). Building a
        # single ``canonical_view`` keyed by canonical would silently
        # drop one of the two values. Mirror the merge-conflict
        # semantics from the variadic / overflow paths: redact each
        # bucket independently, keyed by the ORIGINAL wrapper name, so
        # both buckets round-trip with their own redaction record.
        redacted_kwargs: dict[str, Any] = {}
        for k, v in kwargs.items():
            canonical = _to_canonical(k)
            single_redacted = _redact_named(
                {canonical: v}, tool_name=tool_name, policy=policy
            )
            redacted_kwargs[k] = single_redacted[canonical]
    else:
        redacted_kwargs = _redact_named(
            kwargs, tool_name=tool_name, policy=policy
        )
    if not positional_names:
        # No name information at all. Forward args raw; kwargs were
        # redacted already.
        return list(args), redacted_kwargs

    if skip_kwarg_filled_slots:
        # Map kwarg keys through the alias to compare against canonical
        # slot names declared in the table. Without aliasing, the kwarg
        # keys ARE canonical (because `positional_names` for the no-alias
        # path comes from the chio-default canonical table).
        kwarg_canonicals = {_to_canonical(k) for k in kwargs}
        filled_by_kwarg: set[str] = {
            slot for slot in positional_names if slot in kwarg_canonicals
        }
        slot_sequence: list[str] = [
            slot for slot in positional_names if slot not in filled_by_kwarg
        ]
    else:
        slot_sequence = list(positional_names)
        filled_by_kwarg = set()

    # When an alias map is in play, the positional_names entries are
    # WRAPPER names (e.g. ``("path", "body")``); redact under canonical
    # names by mapping each slot through the alias. Without an alias
    # map, the slot IS its canonical name (chio-default table) and the
    # mapping is identity.
    def _slot_canonical(slot_name: str) -> str:
        return _to_canonical(slot_name)

    named_from_positional: dict[str, Any] = {}
    positional_to_slot: list[str | None] = []
    # Track wrapper-slot-name -> canonical so the redact pass keys by
    # canonical and the rebuild looks values up by wrapper-slot-name.
    slot_to_canonical: dict[str, str] = {}
    # When skip_kwarg_filled_slots is set, positional args that overflow
    # the free-slot sequence may still belong to a protected canonical
    # slot the kwarg already named. Pure-forwarder duplicate-slot calls
    # such as ``proxy('/tmp/x', 'POS_SECRET', content='KW_SECRET')`` for
    # ``chio_file_write`` need the second positional ``POS_SECRET``
    # redacted under the canonical ``content`` slot, not forwarded raw.
    # Mirror the fixed-signature merge-conflict semantics: redact both
    # the positional value and the kwarg value independently.
    overflow_pos_idx = 0
    overflow_slots = (
        [slot for slot in positional_names if slot in filled_by_kwarg]
        if skip_kwarg_filled_slots
        else []
    )
    # Track which canonicals have already been claimed by a non-sentinel
    # named_from_positional entry. Two distinct wrapper slot names can
    # collide on the same canonical (e.g. ``def write_file(label, body,
    # path)`` for chio_file_write whose alias map sends both ``label``
    # and ``body`` to canonical ``content``). Without per-position
    # routing the second slot's bare-name entry would survive in
    # named_from_positional but the canonical-keyed redact view would
    # drop one slot, and the rebuild would KeyError when looking up the
    # missing wrapper-name. Mirror the overflow path: route the
    # colliding slots through the sentinel/per-position redact pass so
    # each value gets its own redacted record.
    canonicals_claimed: set[str] = set()
    for idx, value in enumerate(args):
        if idx < len(slot_sequence):
            slot = slot_sequence[idx]
            canonical_for_slot = _slot_canonical(slot)
            slot_to_canonical[slot] = canonical_for_slot
            # When the slot_sequence contains repeated names (the
            # variadic-padding case ``extended_positional_names ==
            # ("content", "content", "content")`` for ``def
            # write_file(*content)``), keying ``named_from_positional``
            # by the bare slot name silently overwrites earlier values,
            # so every rebuilt position would resolve to the LAST
            # value's redacted record. Detect the duplicate and re-use
            # the same positional-index sentinel approach as the
            # overflow path so each value redacts and rebuilds
            # independently.
            #
            # Distinct slot names can also collide on the SAME canonical
            # when the alias map fans two wrappers onto one protected
            # field (the ``def write_file(label, body, path)`` shape for
            # chio_file_write under the ambiguous-fail-closed cycling).
            # The bare-slot dict entry survives, but the canonical-keyed
            # redact view drops one of the two slots, and the rebuild
            # KeyErrors on the missing wrapper-name. Route the colliding
            # slot through the sentinel path too so every position keeps
            # its own redacted record.
            if (
                slot in named_from_positional
                or canonical_for_slot in canonicals_claimed
            ):
                sentinel_key = f"__overflow_{idx}__{slot}"
                named_from_positional[sentinel_key] = value
                positional_to_slot.append(sentinel_key)
                continue
            named_from_positional[slot] = value
            canonicals_claimed.add(canonical_for_slot)
            positional_to_slot.append(slot)
            continue
        if overflow_pos_idx < len(overflow_slots):
            slot = overflow_slots[overflow_pos_idx]
            overflow_pos_idx += 1
            slot_to_canonical[slot] = _slot_canonical(slot)
            # Redact this positional under the duplicate canonical slot
            # name independently of the kwarg redaction below. We feed it
            # through a private key so it does not collide with the
            # kwarg's own value in ``named_from_positional``.
            sentinel_key = f"__overflow_{idx}__{slot}"
            named_from_positional[sentinel_key] = value
            # The redaction policy is keyed by canonical name, not by
            # this private sentinel, so do the redact under the real slot
            # name and stash via the sentinel for the rebuild step.
            positional_to_slot.append(sentinel_key)
            continue
        positional_to_slot.append(None)
    # Build a name-keyed view for redaction. For the overflow sentinels
    # we substitute the real slot name during the redact pass so the
    # policy lookup matches; the rebuild step then uses the sentinel to
    # locate the redacted value back in the dict. Slot names are mapped
    # through ``_slot_canonical`` so wrapper-renamed slots redact via
    # the canonical name.
    redact_view: dict[str, Any] = {}
    sentinel_to_slot: dict[str, str] = {}
    for key, value in named_from_positional.items():
        if key.startswith("__overflow_"):
            slot = key.rsplit("__", 1)[-1]
            sentinel_to_slot[key] = slot
            canonical_slot = _slot_canonical(slot)
            # Redact each overflow value independently by giving it its
            # own keyed entry under the canonical slot name; we run the
            # redact pass per overflow so values do not overwrite each
            # other in the dict view.
            single_redacted = _redact_named(
                {canonical_slot: value}, tool_name=tool_name, policy=policy
            )
            redact_view[key] = single_redacted[canonical_slot]
        else:
            redact_view[key] = value
    # Redact the non-overflow named slots in one pass. Each slot's
    # value is keyed by the slot's canonical name so the policy lookup
    # matches the protected canonical (e.g. ``content``) even when the
    # wrapper renames the slot (e.g. ``body``).
    non_overflow_view: dict[str, Any] = {}
    canonical_to_slot: dict[str, str] = {}
    for k, v in redact_view.items():
        if k in sentinel_to_slot:
            continue
        canonical = slot_to_canonical.get(k, k)
        non_overflow_view[canonical] = v
        canonical_to_slot[canonical] = k
    redacted_canonical_named = _redact_named(
        non_overflow_view, tool_name=tool_name, policy=policy
    )
    redacted_named: dict[str, Any] = {
        canonical_to_slot[c]: v for c, v in redacted_canonical_named.items()
    }
    # Re-inject the per-overflow redacted values; they were redacted
    # individually above so the policy already applied.
    for sentinel_key in sentinel_to_slot:
        redacted_named[sentinel_key] = redact_view[sentinel_key]
    rebuilt_args: list[Any] = []
    for idx, value in enumerate(args):
        slot_or_sentinel: str | None = positional_to_slot[idx]
        if slot_or_sentinel is not None:
            rebuilt_args.append(redacted_named[slot_or_sentinel])
        else:
            # Extras beyond the table entry stay positional and raw.
            rebuilt_args.append(value)
    return rebuilt_args, redacted_kwargs


__all__ = [
    "DEFAULT_TOOL_POSITIONAL_NAMES",
    "RedactArgs",
    "RedactionPolicy",
    "bind_and_redact",
    "build_alias_map",
    "redact_args",
]
