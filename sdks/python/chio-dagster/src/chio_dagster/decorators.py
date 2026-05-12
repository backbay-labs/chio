"""Chio-governed Dagster decorators.

:func:`chio_asset` wraps Dagster's :func:`dagster.asset` so every asset
materialization flows through the Chio sidecar for capability-scoped
authorisation. :func:`chio_op` wraps :func:`dagster.op` with the same
pre-execute gate.

The decorators preserve Dagster's compute-function contract: the wrapped
function still receives its :class:`dagster.AssetExecutionContext` (or
:class:`dagster.OpExecutionContext`) plus any upstream inputs, and may
return the same values it always would (plain objects,
:class:`dagster.MaterializeResult`, etc.). The wrapper inserts exactly
one sidecar round-trip before the body runs.

Denied materializations raise :class:`PermissionError` so Dagster marks
the run as failed, and the wrapper attaches the deny receipt id and
reason to the :class:`dagster.OpExecutionContext` via
``add_output_metadata`` so the failure surfaces on the Dagster UI.

Allow verdicts attach the receipt id, capability id, tool server, and
partition key (when present) as :class:`dagster.MetadataValue` entries
so the Dagster UI renders the receipt on every successful asset
materialization row.

Partition scoping
-----------------

If the materialization targets a partitioned asset, the wrapper reads
the partition key from the execution context and includes it in the
capability evaluation payload under ``parameters["partition"]`` and in a
mirrored top-level ``parameters["partition_key"]`` key. Guards can then
enforce per-partition access (the canonical ``region=eu-west`` data
residency pattern).
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, cast, overload

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_dagster.errors import ChioDagsterConfigError, ChioDagsterError
from chio_dagster.partitions import extract_partition_info

# Anything that quacks like an :class:`chio_sdk.ChioClient` -- we accept the
# real client and :class:`chio_sdk.testing.MockChioClient` interchangeably.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# ChioClient ownership -- close clients we minted, leave caller clients alone.
# ---------------------------------------------------------------------------


class _ChioClientOwner:
    """Owns a lazily-constructed :class:`ChioClient` for a single call."""

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(
        self, *, client: ChioClientLike | None, sidecar_url: str
    ) -> None:
        self._client = client
        self._owns = client is None
        self._sidecar_url = sidecar_url

    def get(self) -> ChioClientLike:
        if self._client is None:
            self._client = ChioClient(self._sidecar_url)
        return self._client

    async def close(self) -> None:
        if self._owns and self._client is not None:
            try:
                await self._client.close()
            finally:
                self._client = None


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------


def _context_run_id(context: Any) -> str | None:
    """Best-effort extraction of the Dagster run id from a context.

    Dagster exposes the run id via ``context.run.run_id`` on newer
    versions (``context.run_id`` was deprecated in Dagster 1.8). We try
    the newer surface first and fall back to the legacy property so we
    work across the supported version range without emitting deprecation
    warnings on 1.8+.
    """
    try:
        run = getattr(context, "run", None)
        if run is not None:
            run_id = getattr(run, "run_id", None)
            if run_id:
                return str(run_id)
    except Exception:
        pass
    try:
        run_id = getattr(context, "run_id", None)
        if run_id:
            return str(run_id)
    except Exception:
        pass
    return None


def _context_asset_key(context: Any) -> str | None:
    """Best-effort ``asset_key.to_user_string()`` extraction."""
    try:
        asset_key = getattr(context, "asset_key", None)
        if asset_key is None:
            return None
        to_user = getattr(asset_key, "to_user_string", None)
        if callable(to_user):
            return str(to_user())
        return str(asset_key)
    except Exception:
        return None


def _context_log(context: Any, level: str, message: str) -> None:
    """Log via ``context.log`` when available, silently otherwise."""
    try:
        log = getattr(context, "log", None)
        if log is None:
            return
        fn = getattr(log, level, None)
        if callable(fn):
            fn(message)
    except Exception:
        pass


def _find_context_argument(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any | None:
    """Pick the Dagster execution context out of a compute-fn call.

    Dagster passes the context either as the first positional argument
    or as a keyword argument named ``context``. We do not require the
    argument; ops / assets that opt out of the context object work
    without one, in which case the wrapper falls back to a
    partition-less evaluation.
    """
    if args:
        candidate = args[0]
        if _looks_like_dagster_context(candidate):
            return candidate
    return kwargs.get("context")


def _looks_like_dagster_context(value: Any) -> bool:
    """Heuristic: does ``value`` expose the Dagster context surface?"""
    return hasattr(value, "has_partition_key") or hasattr(value, "run_id")


# ---------------------------------------------------------------------------
# Parameter canonicalisation
# ---------------------------------------------------------------------------


def _compute_parameters(
    *,
    context: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    redaction_policy: RedactionPolicy,
) -> dict[str, Any]:
    """Canonicalise the compute-fn arguments + partition into a sidecar payload.

    We deliberately do NOT forward raw upstream objects -- they may not
    be JSON-serialisable (DataFrames, numpy arrays, ...). Instead we
    record the asset / op name and the partition info the policy needs
    to make a routing decision. Callers that need to pass specific
    scalar arguments to guards can forward them via ``tool_name`` or via
    a custom ``parameters`` dict resolved outside this helper.

    Two complementary kwargs passes run before the payload is emitted:

    1. :func:`chio_adapter_base.redact.redact_args` runs FIRST as the
       credential-redaction pass. It replaces secret-bearing fields
       (``chio_file_write.content``, ``chio_file_edit.patch``, plus any
       extras the caller registered on ``redaction_policy``) with a
       ``{"omitted": True, "byte_count": N}`` stub so raw secret bytes
       never reach the receipt log.
    2. :func:`_sanitise_kwargs` runs SECOND as the JSON-safety pass. It
       strips the Dagster ``context`` argument and replaces any value
       that is not JSON-serialisable with a ``{"__chio_type__": ...}``
       marker so the sidecar's canonicalisation step does not blow up
       on DataFrames, numpy arrays, and other rich Python objects.

    The two passes solve different problems (security vs serialisability)
    and both apply on every call.
    """
    partition = extract_partition_info(context) if context is not None else {}
    redacted = redact_args(tool_name, kwargs, policy=redaction_policy)
    payload: dict[str, Any] = {
        "asset": tool_name,
        "kwargs": _sanitise_kwargs(redacted),
    }
    if partition:
        # ``partition`` is the structured dict (key + optional range).
        payload["partition"] = dict(partition)
        # Mirror the primary key at the top level so guards written for
        # the Dagster documentation's canonical shape keep working.
        if "partition_key" in partition:
            payload["partition_key"] = partition["partition_key"]
    _ = args  # Positional upstream inputs are not forwarded -- see docstring.
    return payload


def _sanitise_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """JSON-safety pass: strip non-serialisable values from ``kwargs``.

    Runs AFTER :func:`chio_adapter_base.redact.redact_args` so any
    secret-bearing fields have already been replaced with omission
    stubs. This pass exists for a different reason: the sidecar
    canonicalises whatever we send to JSON for the parameter hash, so
    we drop anything that would break the serialisation. A
    caller-supplied upstream asset (``pd.DataFrame``, ``np.ndarray``,
    ...) is represented by its type name so guards can still reason
    about "an input of type X was present".

    Together with :func:`redact_args` this forms a two-pass pipeline:

    * :func:`redact_args` -- credential redaction (security).
    * :func:`_sanitise_kwargs` -- non-JSON value substitution
      (serialisability).

    The passes are complementary, not duplicate.
    """
    result: dict[str, Any] = {}
    for key, value in kwargs.items():
        if key == "context":
            continue
        if _is_json_safe(value):
            result[key] = value
        else:
            result[key] = {"__chio_type__": type(value).__name__}
    return result


def _is_json_safe(value: Any) -> bool:
    """Return ``True`` for values safe to embed in the sidecar payload."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v) for k, v in value.items()
        )
    return False


# ---------------------------------------------------------------------------
# Core evaluation -- call the sidecar, raise on deny, return the receipt.
# ---------------------------------------------------------------------------


async def _evaluate(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ChioReceipt:
    """Evaluate a materialization via the Chio sidecar.

    Returns the :class:`ChioReceipt`. Raises :class:`ChioDeniedError`
    through on deny-path-403 (caller converts to
    :class:`PermissionError`) and returns a deny receipt on the
    receipt-path deny.
    """
    return await chio_client.evaluate_tool_call(
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        parameters=parameters,
    )


def _denied_permission_error(
    *,
    asset_or_op: str,
    kind: str,
    partition_key: str | None,
    run_id: str | None,
    capability_id: str | None,
    tool_server: str | None,
    reason: str,
    guard: str | None,
    receipt_id: str | None,
    decision: dict[str, Any] | None = None,
) -> PermissionError:
    """Build the :class:`PermissionError` the decorator raises on deny.

    The :class:`ChioDagsterError` rides along on ``chio_error`` (set as an
    attribute, not via ``__cause__``, so callers can recover the
    structured payload after ``except PermissionError``).
    """
    err = ChioDagsterError(
        reason,
        asset_key=asset_or_op if kind == "asset" else None,
        op_name=asset_or_op if kind == "op" else None,
        partition_key=partition_key,
        run_id=run_id,
        capability_id=capability_id,
        tool_server=tool_server,
        guard=guard,
        reason=reason,
        receipt_id=receipt_id,
        decision=decision,
    )
    permission_error = PermissionError(f"Chio capability denied: {reason}")
    permission_error.chio_error = err  # type: ignore[attr-defined]
    return permission_error


# ---------------------------------------------------------------------------
# Receipt metadata helpers
# ---------------------------------------------------------------------------


def _attach_receipt_metadata(
    context: Any,
    *,
    receipt: ChioReceipt,
    partition_key: str | None,
) -> None:
    """Attach the allow-receipt fields to Dagster asset metadata.

    Dagster's :class:`AssetExecutionContext` and :class:`OpExecutionContext`
    expose :meth:`add_output_metadata` (the canonical surface for
    attaching :class:`MetadataValue` entries to the emitted
    :class:`AssetMaterialization`). We import :class:`MetadataValue`
    lazily so this module imports cleanly when Dagster is absent (for
    example, during type-only imports in tests).
    """
    try:
        from dagster import MetadataValue
    except Exception:  # pragma: no cover -- lazy import guard
        return

    add_metadata = getattr(context, "add_output_metadata", None)
    if not callable(add_metadata):
        return

    metadata: dict[str, Any] = {
        "chio_receipt_id": MetadataValue.text(str(receipt.id)),
        "chio_verdict": MetadataValue.text("allow"),
    }
    if receipt.capability_id:
        metadata["chio_capability_id"] = MetadataValue.text(
            str(receipt.capability_id)
        )
    if receipt.tool_server:
        metadata["chio_tool_server"] = MetadataValue.text(
            str(receipt.tool_server)
        )
    if receipt.tool_name:
        metadata["chio_tool_name"] = MetadataValue.text(str(receipt.tool_name))
    if partition_key is not None:
        metadata["chio_partition_key"] = MetadataValue.text(partition_key)

    try:
        add_metadata(metadata)
    except Exception:  # noqa: BLE001 -- metadata emission never fails runs
        pass


def _attach_deny_metadata(
    context: Any,
    *,
    receipt_id: str | None,
    reason: str,
    guard: str | None,
    partition_key: str | None,
) -> None:
    """Attach deny-context fields to Dagster output metadata on failure.

    Dagster still records ``add_output_metadata`` entries on a failed
    op, so this surfaces the deny reason on the Dagster UI even though
    the run transitions to a ``FAILURE`` state.
    """
    try:
        from dagster import MetadataValue
    except Exception:  # pragma: no cover -- lazy import guard
        return

    add_metadata = getattr(context, "add_output_metadata", None)
    if not callable(add_metadata):
        return

    metadata: dict[str, Any] = {
        "chio_verdict": MetadataValue.text("deny"),
        "chio_reason": MetadataValue.text(reason),
    }
    if receipt_id:
        metadata["chio_receipt_id"] = MetadataValue.text(str(receipt_id))
    if guard:
        metadata["chio_guard"] = MetadataValue.text(str(guard))
    if partition_key is not None:
        metadata["chio_partition_key"] = MetadataValue.text(partition_key)

    try:
        add_metadata(metadata)
    except Exception:  # noqa: BLE001 -- metadata emission never fails runs
        pass


# ---------------------------------------------------------------------------
# Shared pre-dispatch body for assets and ops
# ---------------------------------------------------------------------------


async def _run_with_guard(
    *,
    fn: Callable[..., Any],
    kind: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    scope: ChioScope | None,
    capability_id: str | None,
    tool_server: str | None,
    chio_client: ChioClientLike | None,
    sidecar_url: str | None,
    redaction_policy: RedactionPolicy,
    is_async: bool,
) -> Any:
    """Shared evaluate-then-invoke path for :func:`chio_asset` / :func:`chio_op`.

    Runs the sidecar evaluation, attaches the receipt (or deny context)
    to the Dagster execution context, then invokes the original compute
    function. Sync bodies run inline; async bodies are awaited.
    """
    if not capability_id:
        raise ChioDagsterConfigError(
            f"chio_{kind} {tool_name!r} requires a capability_id"
        )
    resolved_tool_server = tool_server or ""
    context = _find_context_argument(args, kwargs)
    partition_info = extract_partition_info(context) if context is not None else {}
    partition_key: str | None = partition_info.get("partition_key")
    run_id = _context_run_id(context) if context is not None else None

    parameters = _compute_parameters(
        context=context,
        args=args,
        kwargs=kwargs,
        tool_name=tool_name,
        redaction_policy=redaction_policy,
    )

    resolved_sidecar = sidecar_url or ChioClient.DEFAULT_BASE_URL
    owner = _ChioClientOwner(client=chio_client, sidecar_url=resolved_sidecar)
    try:
        try:
            receipt = await _evaluate(
                chio_client=owner.get(),
                capability_id=capability_id,
                tool_server=resolved_tool_server,
                tool_name=tool_name,
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            # HTTP-403 path -- no full receipt body, translate directly.
            reason = exc.reason or exc.message
            _attach_deny_metadata(
                context,
                receipt_id=exc.receipt_id,
                reason=reason,
                guard=exc.guard,
                partition_key=partition_key,
            )
            _context_log(
                context,
                "error",
                f"Chio denied {kind} {tool_name!r}: {reason}",
            )
            raise _denied_permission_error(
                asset_or_op=tool_name,
                kind=kind,
                partition_key=partition_key,
                run_id=run_id,
                capability_id=capability_id,
                tool_server=resolved_tool_server,
                reason=reason,
                guard=exc.guard,
                receipt_id=exc.receipt_id,
            ) from exc
        except ChioError:
            # Transport / kernel outage -- let Dagster apply its retry
            # policy rather than translating to PermissionError.
            raise
    finally:
        await owner.close()

    if receipt.is_denied:
        decision = receipt.decision
        reason = decision.reason or "denied by Chio kernel"
        _attach_deny_metadata(
            context,
            receipt_id=receipt.id,
            reason=reason,
            guard=decision.guard,
            partition_key=partition_key,
        )
        _context_log(
            context,
            "error",
            f"Chio denied {kind} {tool_name!r}: {reason}",
        )
        raise _denied_permission_error(
            asset_or_op=tool_name,
            kind=kind,
            partition_key=partition_key,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=resolved_tool_server,
            reason=reason,
            guard=decision.guard,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )

    # Allow path -- log, attach metadata, scope unused but retained for
    # future guard-composition integrations.
    _ = scope
    _attach_receipt_metadata(
        context,
        receipt=receipt,
        partition_key=partition_key,
    )
    _context_log(
        context,
        "info",
        f"Chio allow receipt {receipt.id} for {kind} {tool_name!r}",
    )

    if is_async:
        return await fn(*args, **kwargs)
    return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# @chio_asset
# ---------------------------------------------------------------------------


@overload
def chio_asset(
    __fn: F,
) -> F: ...


@overload
def chio_asset(
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **asset_options: Any,
) -> Callable[[F], F]: ...


def chio_asset(
    __fn: F | None = None,
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **asset_options: Any,
) -> Any:
    """Decorator that wraps a compute function as an Chio-governed Dagster asset.

    Parameters
    ----------
    scope:
        The asset's :class:`ChioScope`. Currently forwarded to the
        receipt metadata; reserved for future per-asset scope
        attenuation against a wrapping :func:`chio_job` context.
    capability_id:
        Pre-minted capability id to evaluate against. Required -- a
        missing capability id raises :class:`ChioDagsterConfigError` at
        materialization time.
    tool_server:
        Chio tool server id for this asset's evaluation. Defaults to an
        empty string; concrete deployments should set this to the
        server that implements the asset's backing tool.
    tool_name:
        Chio tool name to use for evaluation. Defaults to the compute
        function name (which matches Dagster's default asset key).
    chio_client:
        Optional :class:`chio_sdk.ChioClient` (or mock) to use instead of
        minting a default one. The decorator does not close
        caller-owned clients; it only closes clients it created.
    sidecar_url:
        Base URL of the Chio sidecar when the decorator has to mint its
        own client. Defaults to ``http://127.0.0.1:9090``.
    redaction_policy:
        Per-tool credential-redaction policy applied to ``kwargs`` BEFORE
        the JSON-safety pass so secret-bearing fields (``content``,
        ``patch``, ...) are never written to the receipt log. Defaults
        to :meth:`RedactionPolicy.chio_default`. The redaction pass and
        the existing :func:`_sanitise_kwargs` JSON-safety pass are
        complementary -- redaction handles secrets, sanitisation handles
        non-serialisable objects -- and both apply on every call.
    asset_options:
        Forwarded verbatim to :func:`dagster.asset` (e.g.
        ``partitions_def``, ``ins``, ``deps``, ``io_manager_key``,
        ``group_name``, ``metadata``, ``description``). The wrapper
        preserves Dagster's sync contract -- async compute functions
        are supported as well and the wrapper runs them on a fresh
        event loop when Dagster invokes them synchronously.
    """
    from dagster import asset as dagster_asset

    resolved_policy = (
        redaction_policy
        if redaction_policy is not None
        else RedactionPolicy.chio_default()
    )

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__
        asset_kwargs = dict(asset_options)
        asset_kwargs.setdefault("name", resolved_tool_name)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            def async_body(*args: Any, **kwargs: Any) -> Any:
                return asyncio.run(
                    _run_with_guard(
                        fn=fn,
                        kind="asset",
                        args=args,
                        kwargs=kwargs,
                        tool_name=resolved_tool_name,
                        scope=scope,
                        capability_id=capability_id,
                        tool_server=tool_server,
                        chio_client=chio_client,
                        sidecar_url=sidecar_url,
                        redaction_policy=resolved_policy,
                        is_async=True,
                    )
                )

            return cast(F, dagster_asset(**asset_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(
                _run_with_guard(
                    fn=fn,
                    kind="asset",
                    args=args,
                    kwargs=kwargs,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    chio_client=chio_client,
                    sidecar_url=sidecar_url,
                    redaction_policy=resolved_policy,
                    is_async=False,
                )
            )

        return cast(F, dagster_asset(**asset_kwargs)(sync_body))

    if __fn is not None:
        return decorator(__fn)
    return decorator


# ---------------------------------------------------------------------------
# @chio_op
# ---------------------------------------------------------------------------


@overload
def chio_op(
    __fn: F,
) -> F: ...


@overload
def chio_op(
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **op_options: Any,
) -> Callable[[F], F]: ...


def chio_op(
    __fn: F | None = None,
    *,
    scope: ChioScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
    **op_options: Any,
) -> Any:
    """Decorator that wraps a compute function as an Chio-governed Dagster op.

    Semantics mirror :func:`chio_asset` -- a pre-execute capability check
    gates the op body, allow verdicts run the body and attach the
    receipt to the op's output metadata, deny verdicts raise
    :class:`PermissionError` so Dagster records a ``FAILURE`` state.

    ``redaction_policy`` mirrors :func:`chio_asset` and runs as the
    credential-redaction pass before :func:`_sanitise_kwargs` runs the
    JSON-safety pass.

    ``op_options`` forward to :func:`dagster.op` verbatim (e.g. ``ins``,
    ``out``, ``config_schema``, ``retry_policy``, ``tags``).
    """
    from dagster import op as dagster_op

    resolved_policy = (
        redaction_policy
        if redaction_policy is not None
        else RedactionPolicy.chio_default()
    )

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__
        op_kwargs = dict(op_options)
        op_kwargs.setdefault("name", resolved_tool_name)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            def async_body(*args: Any, **kwargs: Any) -> Any:
                return asyncio.run(
                    _run_with_guard(
                        fn=fn,
                        kind="op",
                        args=args,
                        kwargs=kwargs,
                        tool_name=resolved_tool_name,
                        scope=scope,
                        capability_id=capability_id,
                        tool_server=tool_server,
                        chio_client=chio_client,
                        sidecar_url=sidecar_url,
                        redaction_policy=resolved_policy,
                        is_async=True,
                    )
                )

            return cast(F, dagster_op(**op_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(
                _run_with_guard(
                    fn=fn,
                    kind="op",
                    args=args,
                    kwargs=kwargs,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    chio_client=chio_client,
                    sidecar_url=sidecar_url,
                    redaction_policy=resolved_policy,
                    is_async=False,
                )
            )

        return cast(F, dagster_op(**op_kwargs)(sync_body))

    if __fn is not None:
        return decorator(__fn)
    return decorator


__all__ = [
    "ChioClientLike",
    "chio_asset",
    "chio_op",
]
