"""LangSmith bridge for Chio receipts.

The bridge consumes :class:`chio_sdk.models.ChioReceipt` objects and
POSTs them as LangSmith ``Run`` objects via the ``langsmith-sdk``
client. Each receipt becomes one run with:

* ``name`` = ``receipt.tool_name``
* ``run_type`` = ``"tool"``
* ``inputs`` = ``receipt.action.parameters`` (optionally truncated)
* ``outputs`` = ``{decision, evidence, result?}``
* ``tags`` = ``[chio.verdict:*, chio.tool:*, chio.guard:*, chio.cost:*]``
* ``extra.metadata`` = capability id, receipt id, policy hash, cost,
  guard evidence (via :class:`chio_observability.enricher.ReceiptEnricher`).

LangSmith is imported lazily so the rest of this package is usable
without the ``langsmith`` extra installed.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Protocol

from chio_sdk.models import ChioReceipt

from chio_observability.enricher import ReceiptEnricher, SpanPayload
from chio_observability.errors import ChioObservabilityConfigError, ChioObservabilityError

if TYPE_CHECKING:
    from langsmith import Client as _LangSmithClient
else:
    _LangSmithClient = Any  # pragma: no cover - runtime fallback


class _SupportsLangSmithCreateRun(Protocol):
    """Minimal duck-typed interface used by the bridge.

    Tests substitute a test double implementing this protocol; the real
    :class:`langsmith.Client` satisfies it.
    """

    def create_run(self, **kwargs: Any) -> Any:
        ...


class LangSmithBridge:
    """Publish Chio receipts as LangSmith ``Run`` objects.

    Parameters
    ----------
    api_key:
        LangSmith API key. Passed to :class:`langsmith.Client`.
    project:
        LangSmith project name that new runs are attached to.
    api_url:
        Optional LangSmith endpoint override (for self-hosted / Smith-
        compatible deployments).
    client:
        Optional pre-built LangSmith client (or any object satisfying
        :class:`_SupportsLangSmithCreateRun`). When supplied the
        ``api_key`` / ``api_url`` arguments are ignored. Tests use this
        to inject a test double.
    enricher:
        Optional :class:`ReceiptEnricher` override. Defaults to a
        fresh enricher with no default tags.
    """

    BACKEND_NAME = "langsmith"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        project: str | None = None,
        api_url: str | None = None,
        client: _SupportsLangSmithCreateRun | None = None,
        enricher: ReceiptEnricher | None = None,
    ) -> None:
        if client is None:
            if not api_key:
                raise ChioObservabilityConfigError(
                    "LangSmithBridge requires either a langsmith client or an api_key"
                )
            if not project:
                raise ChioObservabilityConfigError(
                    "LangSmithBridge requires a project name"
                )
            client = _build_langsmith_client(api_key=api_key, api_url=api_url)
        else:
            # ``project`` is optional when a custom client is injected,
            # but we still surface a clear error when nothing is set
            # because LangSmith runs without a project float in the
            # default bucket which operators rarely want.
            if not project:
                raise ChioObservabilityConfigError(
                    "LangSmithBridge requires a project name"
                )

        self._client: _SupportsLangSmithCreateRun = client
        self._project = project
        self._enricher = enricher or ReceiptEnricher()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def project(self) -> str:
        """The LangSmith project runs are published to."""
        return self._project

    @property
    def enricher(self) -> ReceiptEnricher:
        """The :class:`ReceiptEnricher` used to build span payloads."""
        return self._enricher

    def publish(
        self,
        receipt: ChioReceipt,
        *,
        tool_result: Any | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Publish a single Chio receipt as a LangSmith run.

        Returns the request payload that was sent to LangSmith, so
        callers can log / assert on the exact span shape.
        """
        payload = self._enricher.enrich(
            receipt,
            tool_result=tool_result,
            error=error,
        )
        request = self._build_run_request(payload)
        try:
            self._client.create_run(**request)
        except Exception as exc:  # noqa: BLE001 -- bubble with context
            raise ChioObservabilityError(
                f"failed to publish LangSmith run for receipt {receipt.id!r}",
                backend=self.BACKEND_NAME,
                receipt_id=receipt.id,
                tool_name=receipt.tool_name,
                cause=exc,
            ) from exc
        return request

    def publish_many(
        self,
        receipts: list[ChioReceipt],
    ) -> list[dict[str, Any]]:
        """Publish a batch of receipts; return the request bodies.

        Receipts that fail raise :class:`ChioObservabilityError`; the
        method stops on the first failure so the caller can decide how
        to handle partial progress.
        """
        return [self.publish(r) for r in receipts]

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    def _build_run_request(self, payload: SpanPayload) -> dict[str, Any]:
        run_id = payload.trace_context.langsmith_run_id or _new_run_id()
        extra: dict[str, Any] = {"metadata": dict(payload.metadata)}
        if payload.guard_evidence:
            extra["guard_evidence"] = [dict(e) for e in payload.guard_evidence]
        if payload.cost_metadata:
            extra["cost"] = dict(payload.cost_metadata)

        request: dict[str, Any] = {
            "id": run_id,
            "name": payload.name,
            "run_type": payload.run_type,
            "inputs": dict(payload.inputs),
            "outputs": dict(payload.outputs),
            "project_name": self._project,
            "tags": list(payload.tags),
            "extra": extra,
        }

        parent_run_id = (
            payload.trace_context.langsmith_parent_run_id
            or payload.trace_context.langsmith_trace_id
        )
        if parent_run_id is not None:
            request["parent_run_id"] = parent_run_id
        if payload.start_time is not None:
            request["start_time"] = payload.start_time
        if payload.end_time is not None:
            request["end_time"] = payload.end_time
        if payload.error is not None:
            request["error"] = payload.error
        return request


def _build_langsmith_client(*, api_key: str, api_url: str | None) -> _LangSmithClient:
    """Build a real LangSmith client, raising a config error if unavailable."""
    try:
        from langsmith import Client
    except ImportError as exc:
        raise ChioObservabilityConfigError(
            "langsmith is not installed -- install chio-observability[langsmith] or "
            "pass a pre-built client to LangSmithBridge"
        ) from exc
    kwargs: dict[str, Any] = {"api_key": api_key}
    if api_url is not None:
        kwargs["api_url"] = api_url
    return Client(**kwargs)


def _new_run_id() -> str:
    """Generate a LangSmith-compatible run id."""
    return str(uuid.uuid4())


__all__ = [
    "LangSmithBridge",
]
