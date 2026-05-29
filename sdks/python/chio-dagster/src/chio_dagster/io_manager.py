"""Chio-governed Dagster :class:`dagster.IOManager` wrapper.

:class:`ChioIOManager` wraps an inner :class:`dagster.IOManager` and
evaluates a Chio capability before every :meth:`load_input` and
:meth:`handle_output` call. Denied I/O raises :class:`PermissionError`
so Dagster records the materialization / input as failed; allow
verdicts delegate to the inner manager unchanged.

This is the natural enforcement point for data-governance guards: the
IO manager knows the destination (warehouse, S3 bucket, local file
store) the asset would land in, and Chio can decide whether a given
capability permits writes to that destination (or reads from it).

Partition keys flow through the evaluation payload: every Dagster
:class:`dagster.OutputContext` / :class:`dagster.InputContext` carries
``has_partition_key`` / ``partition_key``, which we forward under
``parameters["partition"]`` (and mirror at ``parameters["partition_key"]``)
so guards can enforce per-partition write / read policies.
"""

from __future__ import annotations

import asyncio
from typing import Any

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError
from chio_sdk.models import ChioReceipt

from chio_dagster.errors import ChioDagsterConfigError, ChioDagsterError
from chio_dagster.partitions import extract_partition_info

ChioClientLike = Any


class ChioIOManager:
    """Wraps an inner Dagster IO manager with Chio capability checks.

    The wrapper matches the :class:`dagster.IOManager` protocol
    (:meth:`handle_output` + :meth:`load_input`) without inheriting from
    the Dagster base class at import time; the base class is only
    fetched when :meth:`as_io_manager` is called, so importing this
    module does not require Dagster's runtime. Tests that use the
    wrapper directly (without Dagster's resource machinery) can
    instantiate it and call the two methods on fake contexts.

    Parameters
    ----------
    inner:
        The underlying :class:`dagster.IOManager` to delegate to on
        allow. Must implement :meth:`handle_output` and
        :meth:`load_input`.
    capability_id:
        Pre-minted capability id to evaluate I/O against.
    tool_server:
        Chio tool server id used on evaluation (the ``chio_data`` server
        in the canonical example).
    write_tool_name, read_tool_name:
        Chio ``tool_name`` values to pass to the sidecar for
        :meth:`handle_output` / :meth:`load_input`. Defaults:
        ``"io:write"`` / ``"io:read"``.
    chio_client:
        Optional :class:`chio_sdk.ChioClient` (or mock) to use. The
        manager does not close caller-owned clients; it only closes
        clients it created.
    sidecar_url:
        Fallback sidecar URL when the manager has to mint its own
        client. Defaults to ``http://127.0.0.1:9090``.
    """

    def __init__(
        self,
        inner: Any,
        *,
        capability_id: str,
        tool_server: str = "",
        write_tool_name: str = "io:write",
        read_tool_name: str = "io:read",
        chio_client: ChioClientLike | None = None,
        sidecar_url: str | None = None,
    ) -> None:
        if inner is None:
            raise ChioDagsterConfigError(
                "ChioIOManager requires an inner IOManager to delegate to"
            )
        if not capability_id:
            raise ChioDagsterConfigError(
                "ChioIOManager requires a capability_id"
            )
        if not hasattr(inner, "handle_output") or not hasattr(
            inner, "load_input"
        ):
            raise ChioDagsterConfigError(
                "inner IOManager must implement handle_output and load_input"
            )
        self._inner = inner
        self._capability_id = capability_id
        self._tool_server = tool_server
        self._write_tool_name = write_tool_name
        self._read_tool_name = read_tool_name
        self._chio_client = chio_client
        self._sidecar_url = sidecar_url or ChioClient.DEFAULT_BASE_URL
        self._owns_client = chio_client is None

    # ------------------------------------------------------------------
    # IOManager protocol
    # ------------------------------------------------------------------

    def handle_output(self, context: Any, obj: Any) -> None:
        """Evaluate write access, then delegate to the inner manager.

        Raises :class:`PermissionError` on deny. Any evaluation path
        that succeeds proceeds to the inner manager's
        :meth:`handle_output`; failures in the inner manager propagate
        through unchanged so Dagster's retry / alerting behaviour is
        preserved.
        """
        receipt = self._run_evaluation(
            context=context,
            tool_name=self._write_tool_name,
            operation="write",
        )
        _ = receipt  # receipt may be used by downstream integrations
        self._inner.handle_output(context, obj)

    def load_input(self, context: Any) -> Any:
        """Evaluate read access, then delegate to the inner manager."""
        receipt = self._run_evaluation(
            context=context,
            tool_name=self._read_tool_name,
            operation="read",
        )
        _ = receipt
        return self._inner.load_input(context)

    # ------------------------------------------------------------------
    # Async variants -- Dagster 1.8+ exposes optional async IO handles.
    # ------------------------------------------------------------------

    async def handle_output_async(self, context: Any, obj: Any) -> None:
        """Async variant of :meth:`handle_output`."""
        await self._run_evaluation_async(
            context=context,
            tool_name=self._write_tool_name,
            operation="write",
        )
        inner_async = getattr(self._inner, "handle_output_async", None)
        if callable(inner_async):
            await inner_async(context, obj)
            return
        self._inner.handle_output(context, obj)

    async def load_input_async(self, context: Any) -> Any:
        """Async variant of :meth:`load_input`."""
        await self._run_evaluation_async(
            context=context,
            tool_name=self._read_tool_name,
            operation="read",
        )
        inner_async = getattr(self._inner, "load_input_async", None)
        if callable(inner_async):
            return await inner_async(context)
        return self._inner.load_input(context)

    # ------------------------------------------------------------------
    # Dagster integration helpers
    # ------------------------------------------------------------------

    def as_io_manager(self) -> Any:
        """Return a Dagster-registered :class:`dagster.IOManager` subclass.

        Dagster's resource machinery expects an :class:`IOManager`
        subclass instance. We build one lazily so importing
        :mod:`chio_dagster` does not require Dagster at module import
        time (useful for type-only imports and constrained test
        environments).
        """
        from dagster import IOManager as DagsterIOManager

        outer = self

        class _ChioIOManagerAdapter(DagsterIOManager):
            def handle_output(self, context: Any, obj: Any) -> None:
                outer.handle_output(context, obj)

            def load_input(self, context: Any) -> Any:
                return outer.load_input(context)

        return _ChioIOManagerAdapter()

    # ------------------------------------------------------------------
    # Evaluation path
    # ------------------------------------------------------------------

    def _run_evaluation(
        self, *, context: Any, tool_name: str, operation: str
    ) -> ChioReceipt:
        """Synchronous evaluation wrapper (runs the async path on a loop)."""
        return asyncio.run(
            self._run_evaluation_async(
                context=context,
                tool_name=tool_name,
                operation=operation,
            )
        )

    async def _run_evaluation_async(
        self, *, context: Any, tool_name: str, operation: str
    ) -> ChioReceipt:
        """Evaluate via the sidecar; raise :class:`PermissionError` on deny."""
        parameters = self._build_parameters(
            context=context, operation=operation
        )
        partition_info = extract_partition_info(context)
        partition_key = partition_info.get("partition_key")

        client_owned: bool = False
        client = self._chio_client
        if client is None:
            client = ChioClient(self._sidecar_url)
            client_owned = True

        try:
            try:
                receipt = await client.evaluate_tool_call(
                    capability_id=self._capability_id,
                    tool_server=self._tool_server,
                    tool_name=tool_name,
                    parameters=parameters,
                )
            except ChioDeniedError as exc:
                raise self._deny_permission_error(
                    reason=exc.reason or exc.message,
                    guard=exc.guard,
                    receipt_id=exc.receipt_id,
                    tool_name=tool_name,
                    partition_key=partition_key,
                ) from exc
        finally:
            if client_owned:
                try:
                    await client.close()
                except Exception:  # noqa: BLE001 -- close never fails the op
                    pass

        if not receipt.is_allowed:
            decision = receipt.decision
            raise self._deny_permission_error(
                reason=decision.reason
                if decision is not None and decision.reason is not None
                else "non-authorizing Chio receipt",
                guard=decision.guard if decision is not None else None,
                receipt_id=receipt.id,
                tool_name=tool_name,
                partition_key=partition_key,
                decision=decision.model_dump(exclude_none=True)
                if decision is not None
                else None,
            )
        return receipt

    # ------------------------------------------------------------------
    # Payload + error helpers
    # ------------------------------------------------------------------

    def _build_parameters(
        self, *, context: Any, operation: str
    ) -> dict[str, Any]:
        partition_info = extract_partition_info(context)
        asset_key = _asset_key_string(context)
        destination = type(self._inner).__name__
        payload: dict[str, Any] = {
            "operation": operation,
            "destination": destination,
        }
        if asset_key:
            payload["asset"] = asset_key
        if partition_info:
            payload["partition"] = dict(partition_info)
            if "partition_key" in partition_info:
                payload["partition_key"] = partition_info["partition_key"]
        return payload

    def _deny_permission_error(
        self,
        *,
        reason: str,
        guard: str | None,
        receipt_id: str | None,
        tool_name: str,
        partition_key: str | None,
        decision: dict[str, Any] | None = None,
    ) -> PermissionError:
        err = ChioDagsterError(
            reason,
            op_name=tool_name,
            partition_key=partition_key,
            capability_id=self._capability_id,
            tool_server=self._tool_server,
            guard=guard,
            reason=reason,
            receipt_id=receipt_id,
            decision=decision,
        )
        permission_error = PermissionError(
            f"Chio capability denied: {reason}"
        )
        permission_error.chio_error = err  # type: ignore[attr-defined]
        return permission_error


def _asset_key_string(context: Any) -> str | None:
    """Extract ``asset_key.to_user_string()`` from an IO manager context."""
    try:
        asset_key = getattr(context, "asset_key", None)
    except Exception:
        return None
    if asset_key is None:
        return None
    to_user = getattr(asset_key, "to_user_string", None)
    if callable(to_user):
        try:
            return str(to_user())
        except Exception:
            return None
    try:
        return str(asset_key)
    except Exception:
        return None


__all__ = [
    "ChioIOManager",
]
