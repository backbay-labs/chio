"""Chio-governed Dagster decorators.

``@chio_asset`` and ``@chio_op`` insert one Chio sidecar round-trip
before the compute body runs. Denied materializations raise
``PermissionError`` (Dagster marks the run as ``FAILURE``); allow / deny
context is attached via ``add_output_metadata`` so the receipt and
guard reason render on the Dagster UI. Partitioned assets forward
``parameters["partition_key"]`` for per-partition guard decisions.
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

# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


class _ChioClientOwner:
    """Lazy :class:`ChioClient` owner; only closes clients it created itself."""

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


def _context_run_id(context: Any) -> str | None:
    """Best-effort run id extraction; tries Dagster 1.8+ then legacy surface."""
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
    """Pick the Dagster execution context out of a compute-fn call (positional or kw)."""
    if args:
        candidate = args[0]
        if _looks_like_dagster_context(candidate):
            return candidate
    return kwargs.get("context")


def _looks_like_dagster_context(value: Any) -> bool:
    return hasattr(value, "has_partition_key") or hasattr(value, "run_id")


def _compute_parameters(
    *,
    context: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    redaction_policy: RedactionPolicy,
) -> dict[str, Any]:
    """Canonicalise compute-fn args + partition into a JSON-safe sidecar payload.

    Raw upstream objects are NOT forwarded (they may be DataFrames,
    arrays, ...); kwargs flow through :func:`redact_args` then
    :func:`_sanitise_kwargs`.
    """
    partition = extract_partition_info(context) if context is not None else {}
    redacted = redact_args(tool_name, kwargs, policy=redaction_policy)
    payload: dict[str, Any] = {
        "asset": tool_name,
        "kwargs": _sanitise_kwargs(redacted),
    }
    if partition:
        payload["partition"] = dict(partition)
        # Mirror primary key for guards using the canonical Dagster shape.
        if "partition_key" in partition:
            payload["partition_key"] = partition["partition_key"]
    _ = args
    return payload


def _sanitise_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Replace non-JSON-safe values with ``{"__chio_type__": ...}`` markers."""
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
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v) for k, v in value.items()
        )
    return False


async def _evaluate(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ChioReceipt:
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
    """Build the deny PermissionError; structured payload on ``chio_error`` attr."""
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


def _attach_receipt_metadata(
    context: Any,
    *,
    receipt: ChioReceipt,
    partition_key: str | None,
) -> None:
    """Attach allow-receipt fields to Dagster output metadata."""
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
    """Attach deny-context fields to Dagster output metadata (visible on failure)."""
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
    """Shared evaluate-then-invoke path for :func:`chio_asset` / :func:`chio_op`."""
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
            # HTTP 403: no full receipt body.
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
            # Transport / kernel outage; let Dagster retry policy apply.
            raise
    finally:
        await owner.close()

    if not receipt.is_allowed:
        decision = receipt.decision
        reason = (
            decision.reason
            if decision is not None and decision.reason is not None
            else "non-authorizing Chio receipt"
        )
        guard = decision.guard if decision is not None else None
        decision_payload = (
            decision.model_dump(exclude_none=True) if decision is not None else None
        )
        _attach_deny_metadata(
            context,
            receipt_id=receipt.id,
            reason=reason,
            guard=guard,
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
            guard=guard,
            receipt_id=receipt.id,
            decision=decision_payload,
        )

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
    """Wrap a compute function as a Chio-governed Dagster asset.

    ``capability_id`` is required (else :class:`ChioDagsterConfigError`).
    ``tool_name`` defaults to the function name (matches Dagster's
    default asset key). ``redaction_policy`` defaults to
    :meth:`RedactionPolicy.chio_default`. ``**asset_options`` pass
    straight through to :func:`dagster.asset`. Async compute functions
    are supported; the wrapper runs them on a fresh loop when Dagster
    invokes them synchronously.
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
    """Wrap a compute function as a Chio-governed Dagster op.

    Mirrors :func:`chio_asset`. ``**op_options`` pass through to
    :func:`dagster.op`.
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
