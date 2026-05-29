"""Hypothesis property tests for ``bind_and_redact``.

At least 5 properties, each running >= 200 examples on CI. The 6-axis matrix in
``test_bind_and_redact.py`` enumerates representative cells; the
properties below random-sample the combinatoric space to surface
shape combinations the matrix does not name explicitly.

Each property exercises a different invariant:

1. JSON-serialisability of the redacted output.
2. ``bind_and_redact`` never raises for any callable + args + kwargs
   combination (always returns a tuple).
3. Wire-shape preservation: positional values stay in the args bucket,
   kwarg values stay in the kwargs bucket.
4. Determinism: identical inputs yield identical output buckets across
   repeated calls.
5. ``byte_count`` of redacted fields matches the encoded length of the
   original value.
"""

from __future__ import annotations

import json
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Tools the chio-default policy + table know about; bind_and_redact must
# behave for every tool name including unknown ones.
_KNOWN_TOOLS = sorted(DEFAULT_TOOL_POSITIONAL_NAMES.keys())
_TOOL_NAMES = st.one_of(
    st.sampled_from(_KNOWN_TOOLS),
    st.sampled_from(["unknown_tool", "my_upload", "chio_file_read"]),
)

# Scalar values the wrapper functions might receive. Strings cover the
# redaction stub path (byte_count); ints / bools / None cover the
# str()-fallback path inside _byte_count.
_SCALAR = st.one_of(
    st.text(min_size=0, max_size=64),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.none(),
    st.binary(min_size=0, max_size=32),
)

# Field names a caller could plausibly pass as kwargs. Mix of canonical
# names that the policy redacts, wrapper aliases, and unrelated names.
_KWARG_NAMES = st.sampled_from(
    [
        "path",
        "content",
        "patch",
        "body",
        "payload",
        "marker",
        "trace_id",
        "extra",
    ]
)


def _wrappers() -> st.SearchStrategy[Any]:
    """Sample one wrapper-callable shape per draw.

    Each wrapper is picked from a fixed pool so hypothesis can shrink
    failures back to a named shape. The pool spans the matrix axes:
    fixed-positional, kwonly, VAR_POSITIONAL, VAR_KEYWORD, pure
    forwarder, and ``fn=None``.
    """

    def w_fixed(path, content):  # noqa: ANN001, ANN202
        del path, content

    def w_renamed(path, body):  # noqa: ANN001, ANN202
        del path, body

    def w_kwonly(path, *, body):  # noqa: ANN001, ANN202
        del path, body

    def w_varpos(*content):  # noqa: ANN002, ANN202
        del content

    def w_varkw(**kw):  # noqa: ANN003, ANN202
        del kw

    def w_pure(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        del args, kwargs

    return st.sampled_from(
        [w_fixed, w_renamed, w_kwonly, w_varpos, w_varkw, w_pure, None]
    )


# Args sequence: zero to 4 positional values. Wider than the matrix
# enumerates so AP4 (more positional than fixed slots) gets exercised.
_ARGS = st.lists(_SCALAR, min_size=0, max_size=4)

# Kwargs mapping: 0..3 entries; names sampled from the canonical /
# wrapper / unrelated pool to surface alias-collision shapes.
_KWARGS = st.dictionaries(_KWARG_NAMES, _SCALAR, min_size=0, max_size=3)

# Policies under test. ``None`` exercises the chio_default fallback.
_POLICIES = st.one_of(
    st.none(),
    st.builds(
        RedactionPolicy,
        body_fields=st.just(
            {
                "chio_file_write": ("content",),
                "chio_file_edit": ("patch",),
                "my_upload": ("payload",),
            }
        ),
    ),
)


def _is_json_safe(value: Any) -> bool:
    """``True`` iff ``value`` round-trips through ``json.dumps``."""
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True


def _to_json_safe(value: Any) -> Any:
    """Coerce ``value`` to a JSON-safe scalar so the property checks the
    REDACTION OUTPUT rather than the raw input. Bytes do not survive
    ``json.dumps`` natively but the redaction stub always emits a
    JSON-safe dict for protected fields, and we only assert the
    REDACTED value is JSON-safe (raw fields may be bytes).
    """
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    return value


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    fn=_wrappers(),
    args=_ARGS,
    kwargs=_KWARGS,
    tool_name=_TOOL_NAMES,
    policy=_POLICIES,
)
def test_property_redacted_output_is_json_serialisable(
    fn: Any,
    args: list[Any],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: Any,
) -> None:
    """Property 1: the redacted output is JSON-serialisable for any
    well-typed input.

    The receipt-buffer wire shape is JSON. A redacted value that fails
    ``json.dumps`` would corrupt the receipts append path. We coerce
    raw bytes to strings before the call (raw bytes survive
    redaction unchanged; the policy only stubs PROTECTED slots, and a
    bytes value lands in the stub as ``byte_count`` only) so the
    property cleanly tests that REDACTION never introduces a
    non-JSON-safe value.
    """
    safe_args = [_to_json_safe(v) for v in args]
    safe_kwargs = {k: _to_json_safe(v) for k, v in kwargs.items()}
    redacted_args, redacted_kwargs = bind_and_redact(
        fn,
        safe_args,
        safe_kwargs,
        tool_name=tool_name,
        policy=policy,
    )
    # Each redacted bucket must round-trip through json.dumps.
    assert _is_json_safe(redacted_args), redacted_args
    assert _is_json_safe(redacted_kwargs), redacted_kwargs


@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    fn=_wrappers(),
    args=_ARGS,
    kwargs=_KWARGS,
    tool_name=_TOOL_NAMES,
    policy=_POLICIES,
)
def test_property_bind_and_redact_never_raises(
    fn: Any,
    args: list[Any],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: Any,
) -> None:
    """Property 2: ``bind_and_redact`` always returns a 2-tuple of
    (list, dict) for any callable + any positional + any kwargs combo.

    The helper is on the hot path of every adapter hook. A
    bind_partial / TypeError / ValueError that propagates out would
    crash the receipt write. The fail-closed contract requires a
    well-typed return for every shape (even shapes that would TypeError
    if called for real) so the receipt always lands.
    """
    result = bind_and_redact(
        fn, args, kwargs, tool_name=tool_name, policy=policy
    )
    assert isinstance(result, tuple)
    assert len(result) == 2
    redacted_args, redacted_kwargs = result
    assert isinstance(redacted_args, list)
    assert isinstance(redacted_kwargs, dict)


@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    fn=_wrappers(),
    args=_ARGS,
    kwargs=_KWARGS,
    tool_name=_TOOL_NAMES,
    policy=_POLICIES,
)
def test_property_wire_shape_preservation(
    fn: Any,
    args: list[Any],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: Any,
) -> None:
    """Property 3: positional values stay in the args bucket; kwarg
    values stay in the kwargs bucket. The wire shape the caller
    presented is preserved across redaction.

    ``len(redacted_args) == len(args)`` (no positional-to-kwarg
    promotion) and the kwargs key set is the original set (no kwarg-to-
    positional demotion, no key renaming, no alias rewrite leaking
    onto the wire).
    """
    redacted_args, redacted_kwargs = bind_and_redact(
        fn, args, kwargs, tool_name=tool_name, policy=policy
    )
    assert len(redacted_args) == len(args)
    assert set(redacted_kwargs.keys()) == set(kwargs.keys())


@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    fn=_wrappers(),
    args=_ARGS,
    kwargs=_KWARGS,
    tool_name=_TOOL_NAMES,
    policy=_POLICIES,
)
def test_property_redaction_is_deterministic(
    fn: Any,
    args: list[Any],
    kwargs: dict[str, Any],
    tool_name: str,
    policy: Any,
) -> None:
    """Property 4: ``bind_and_redact`` is deterministic for fixed
    inputs. Calling it twice with the same args / kwargs / tool_name /
    policy yields identical output buckets.

    Strict idempotence (``f(f(x)) == f(x)``) does NOT hold because the
    redaction stub is a dict whose ``str()``-form has a different
    byte-count than the original value; running redaction on a stub
    re-hashes the stub. Determinism is the weaker property the receipt
    pipeline actually relies on (parameter-hash stability across the
    same call) and is the wire-shape invariant the helper promises.
    """
    safe_args = [_to_json_safe(v) for v in args]
    safe_kwargs = {k: _to_json_safe(v) for k, v in kwargs.items()}
    first = bind_and_redact(
        fn, safe_args, safe_kwargs, tool_name=tool_name, policy=policy
    )
    second = bind_and_redact(
        fn, safe_args, safe_kwargs, tool_name=tool_name, policy=policy
    )
    assert first == second


@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    args=st.lists(
        st.text(min_size=0, max_size=128), min_size=1, max_size=4
    ),
    kwargs=st.dictionaries(
        _KWARG_NAMES,
        st.text(min_size=0, max_size=128),
        min_size=0,
        max_size=3,
    ),
    tool_name=_TOOL_NAMES,
)
def test_property_redaction_byte_count_matches_encoded_length(
    args: list[str],
    kwargs: dict[str, str],
    tool_name: str,
) -> None:
    """Property 5: every redacted-stub ``byte_count`` equals
    ``len(original.encode("utf-8"))`` for the value at that slot.

    This is the contract the receipt buffer relies on for
    rate-limiting and integrity hashing: the byte_count must be the
    UTF-8 length of the ORIGINAL value, not the stub's own length and
    not a misencoded scalar. Walk the redacted output, locate every
    stub, and cross-reference its byte_count against the corresponding
    input.
    """
    # Use a fixed signature so positional values bind to known slots.
    def write(path: str, content: str) -> None:
        del path, content

    redacted_args, redacted_kwargs = bind_and_redact(
        write, args, kwargs, tool_name=tool_name
    )

    # Walk positional args. For ``chio_file_write`` the second slot is
    # ``content`` and is protected; for any other tool nothing is
    # protected so no stubs appear in args.
    if tool_name == "chio_file_write" and len(args) >= 2:
        # Slot 1 (``content``) is the protected slot.
        stub = redacted_args[1]
        if isinstance(stub, dict) and stub.get("omitted") is True:
            assert stub["byte_count"] == len(args[1].encode("utf-8"))
    if tool_name == "chio_file_edit" and len(args) >= 2:
        # ``chio_file_edit`` protects the second slot too (``patch``).
        stub = redacted_args[1]
        if isinstance(stub, dict) and stub.get("omitted") is True:
            assert stub["byte_count"] == len(args[1].encode("utf-8"))

    # Walk kwargs: any kwarg-key whose canonical name is in the policy
    # for this tool will be a stub; all others are raw.
    for k, raw in kwargs.items():
        out = redacted_kwargs.get(k)
        if isinstance(out, dict) and out.get("omitted") is True:
            assert out["byte_count"] == len(raw.encode("utf-8"))
        else:
            # Unredacted: must be the raw value (no silent rewrite).
            assert out == raw
