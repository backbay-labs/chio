"""LangFuse bridge for Chio receipts.

The bridge consumes :class:`chio_sdk.models.ChioReceipt` objects and
pushes them to LangFuse via the ``langfuse`` SDK as spans attached to
an existing trace (when the receipt carries trace context) or as
standalone traces with a single span (when it does not).

Each receipt becomes one LangFuse span with:

* ``name`` = ``receipt.tool_name``
* ``input`` = ``receipt.action.parameters`` (optionally truncated)
* ``output`` = ``{decision, evidence, result?}``
* ``level`` = ``DEFAULT`` on allow, ``ERROR`` on deny
* ``status_message`` = decision reason (on deny only)
* ``metadata`` = enriched Chio metadata + cost + guard evidence

LangFuse is imported lazily so the rest of this package is usable
without the ``langfuse`` extra installed.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Protocol

from chio_sdk.models import ChioReceipt

from chio_observability.enricher import ReceiptEnricher, SpanPayload
from chio_observability.errors import ChioObservabilityConfigError, ChioObservabilityError

if TYPE_CHECKING:
    from langfuse import Langfuse as _LangFuseClient
else:
    _LangFuseClient = Any  # pragma: no cover - runtime fallback


class _SupportsLangFuseSpan(Protocol):
    """Minimal duck-typed interface used by the bridge.

    The real :class:`langfuse.Langfuse` client and the test double used in
    tests both satisfy this protocol. We accept a loose surface so
    the bridge works across v2 and v3 of the LangFuse SDK.
    """

    def trace(self, **kwargs: Any) -> Any:
        ...

    def span(self, **kwargs: Any) -> Any:
        ...

    def flush(self) -> Any:
        ...


class LangFuseBridge:
    """Publish Chio receipts as LangFuse spans.

    Parameters
    ----------
    public_key:
        LangFuse public key. Also accepted as ``api_key`` for symmetry
        with :class:`LangSmithBridge`.
    secret_key:
        LangFuse secret key; required when ``public_key`` is given.
    host:
        LangFuse endpoint (self-hosted or SaaS).
    api_key:
        Optional alias for ``public_key`` so callers can mirror the
        LangSmith bridge API.
    client:
        Optional pre-built LangFuse client (or any object satisfying
        :class:`_SupportsLangFuseSpan`). When supplied, credentials
        are not re-validated.
    enricher:
        Optional :class:`ReceiptEnricher` override.
    """

    BACKEND_NAME = "langfuse"

    def __init__(
        self,
        *,
        public_key: str | None = None,
        secret_key: str | None = None,
        host: str | None = None,
        api_key: str | None = None,
        client: _SupportsLangFuseSpan | None = None,
        enricher: ReceiptEnricher | None = None,
    ) -> None:
        if client is None:
            resolved_public_key = public_key or api_key
            if not resolved_public_key:
                raise ChioObservabilityConfigError(
                    "LangFuseBridge requires either a langfuse client or public_key/api_key"
                )
            if not secret_key:
                raise ChioObservabilityConfigError(
                    "LangFuseBridge requires a secret_key when building a client"
                )
            if not host:
                raise ChioObservabilityConfigError(
                    "LangFuseBridge requires a host (self-hosted or SaaS) URL"
                )
            client = _build_langfuse_client(
                public_key=resolved_public_key,
                secret_key=secret_key,
                host=host,
            )

        self._client: _SupportsLangFuseSpan = client
        self._host = host
        self._enricher = enricher or ReceiptEnricher()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def enricher(self) -> ReceiptEnricher:
        """The :class:`ReceiptEnricher` used to build span payloads."""
        return self._enricher

    @property
    def host(self) -> str | None:
        """The configured LangFuse host, if any."""
        return self._host

    def publish(
        self,
        receipt: ChioReceipt,
        *,
        tool_result: Any | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Publish a single Chio receipt as a LangFuse span.

        Returns the span kwargs dict that was dispatched so tests and
        logs can assert on the exact payload shape.
        """
        payload = self._enricher.enrich(
            receipt,
            tool_result=tool_result,
            error=error,
        )
        trace_id = self._ensure_trace(payload, receipt)
        span_kwargs = self._build_span_kwargs(payload, trace_id=trace_id)
        try:
            self._client.span(**span_kwargs)
        except Exception as exc:  # noqa: BLE001 -- bubble with context
            raise ChioObservabilityError(
                f"failed to publish LangFuse span for receipt {receipt.id!r}",
                backend=self.BACKEND_NAME,
                receipt_id=receipt.id,
                tool_name=receipt.tool_name,
                cause=exc,
            ) from exc
        return span_kwargs

    def publish_many(
        self,
        receipts: list[ChioReceipt],
    ) -> list[dict[str, Any]]:
        """Publish a batch of receipts; return the span kwargs dispatched.

        Stops on the first failure, re-raising :class:`ChioObservabilityError`.
        """
        return [self.publish(r) for r in receipts]

    def flush(self) -> None:
        """Flush any buffered LangFuse events."""
        try:
            self._client.flush()
        except Exception as exc:  # noqa: BLE001 -- bubble with context
            raise ChioObservabilityError(
                "failed to flush LangFuse client",
                backend=self.BACKEND_NAME,
                cause=exc,
            ) from exc

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    def _ensure_trace(
        self,
        payload: SpanPayload,
        receipt: ChioReceipt,
    ) -> str:
        """Return a trace id, creating a standalone trace if needed.

        Receipts emitted by agent frameworks that propagate LangFuse
        context already carry ``langfuse_trace_id``. If absent, we
        create a synthetic trace per-receipt so that even ungoverned
        callers still end up with navigable LangFuse timelines.
        """
        existing = payload.trace_context.langfuse_trace_id
        if existing:
            return existing

        trace_id = _new_observation_id()
        trace_kwargs: dict[str, Any] = {
            "id": trace_id,
            "name": f"chio.receipt.{receipt.tool_name}",
            "metadata": dict(payload.metadata),
            "tags": list(payload.tags),
        }
        try:
            self._client.trace(**trace_kwargs)
        except Exception as exc:  # noqa: BLE001 -- bubble with context
            raise ChioObservabilityError(
                f"failed to create LangFuse trace for receipt {receipt.id!r}",
                backend=self.BACKEND_NAME,
                receipt_id=receipt.id,
                tool_name=receipt.tool_name,
                cause=exc,
            ) from exc
        return trace_id

    def _build_span_kwargs(
        self,
        payload: SpanPayload,
        *,
        trace_id: str,
    ) -> dict[str, Any]:
        verdict = payload.metadata.get("chio.verdict", "unknown")
        level = "ERROR" if verdict == "deny" else "DEFAULT"

        metadata = dict(payload.metadata)
        if payload.guard_evidence:
            metadata["chio.evidence"] = [dict(e) for e in payload.guard_evidence]
        if payload.cost_metadata:
            metadata["chio.cost"] = dict(payload.cost_metadata)

        span_kwargs: dict[str, Any] = {
            "id": _new_observation_id(),
            "trace_id": trace_id,
            "name": payload.name,
            "input": dict(payload.inputs),
            "output": dict(payload.outputs),
            "metadata": metadata,
            "level": level,
            "tags": list(payload.tags),
        }

        parent = payload.trace_context.langfuse_parent_observation_id
        if parent is not None:
            span_kwargs["parent_observation_id"] = parent
        if payload.start_time is not None:
            span_kwargs["start_time"] = payload.start_time
        if payload.end_time is not None:
            span_kwargs["end_time"] = payload.end_time
        status_message = payload.error or (
            payload.metadata.get("chio.reason") if verdict == "deny" else None
        )
        if status_message is not None:
            span_kwargs["status_message"] = status_message
        return span_kwargs


def _build_langfuse_client(
    *,
    public_key: str,
    secret_key: str,
    host: str,
) -> _LangFuseClient:
    """Build a real LangFuse client, raising a config error if unavailable."""
    try:
        from langfuse import Langfuse
    except ImportError as exc:
        raise ChioObservabilityConfigError(
            "langfuse is not installed -- install chio-observability[langfuse] or "
            "pass a pre-built client to LangFuseBridge"
        ) from exc
    return Langfuse(
        public_key=public_key,
        secret_key=secret_key,
        host=host,
    )


def _new_observation_id() -> str:
    """Generate a LangFuse-compatible observation/trace id."""
    return str(uuid.uuid4())


__all__ = [
    "LangFuseBridge",
]
