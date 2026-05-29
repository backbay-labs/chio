"""Platform-agnostic enrichment of Chio receipts into span payloads.

:class:`ReceiptEnricher` transforms an :class:`chio_sdk.models.ChioReceipt`
into a backend-neutral :class:`SpanPayload` carrying the fields every
agent observability platform needs:

* ``name`` -- the tool name, used as the span display name.
* ``run_type`` -- always ``"tool"`` for Chio receipts so the span renders
  as a tool invocation in LangSmith / LangFuse timelines.
* ``inputs`` -- the tool parameters that were evaluated.
* ``outputs`` -- a structured view of the decision + any tool result the
  caller supplied.
* ``tags`` -- ordered list of short labels (verdict, guards, cost) so
  operators can filter spans by Chio-specific signals.
* ``metadata`` -- dict of Chio-specific attributes (capability id,
  receipt id, policy hash, kernel key, cost, etc.).
* ``trace_context`` -- parent trace / observation ids pulled from
  receipt metadata so downstream bridges can attach spans to the
  originating agent trace instead of creating orphan traces.

Each bridge consumes this payload and maps it to the shape its SDK
expects. Keeping the mapping centralised here means the mapping is
unit-testable in isolation and both bridges stay consistent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from chio_sdk.models import ChioReceipt, GuardEvidence, MonetaryAmount


@dataclass
class TraceContext:
    """Parent trace / observation ids extracted from receipt metadata.

    All fields are optional; a bridge may create a standalone trace
    when none are populated.
    """

    langsmith_run_id: str | None = None
    langsmith_parent_run_id: str | None = None
    langsmith_trace_id: str | None = None
    langfuse_trace_id: str | None = None
    langfuse_parent_observation_id: str | None = None

    def is_empty(self) -> bool:
        """Return ``True`` when no trace-context fields are populated."""
        return all(
            getattr(self, f) is None
            for f in (
                "langsmith_run_id",
                "langsmith_parent_run_id",
                "langsmith_trace_id",
                "langfuse_trace_id",
                "langfuse_parent_observation_id",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Return populated fields as a plain dict."""
        payload: dict[str, Any] = {}
        for field_name in (
            "langsmith_run_id",
            "langsmith_parent_run_id",
            "langsmith_trace_id",
            "langfuse_trace_id",
            "langfuse_parent_observation_id",
        ):
            value = getattr(self, field_name)
            if value is not None:
                payload[field_name] = value
        return payload


@dataclass
class SpanPayload:
    """Backend-neutral span description built from a Chio receipt.

    Bridges consume this and emit platform-specific payloads.
    """

    name: str
    run_type: str
    inputs: dict[str, Any]
    outputs: dict[str, Any]
    tags: list[str]
    metadata: dict[str, Any]
    trace_context: TraceContext
    start_time: int | None
    end_time: int | None
    error: str | None = None
    cost_metadata: dict[str, Any] = field(default_factory=dict)
    guard_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the span payload as a plain dict for logging / tests."""
        payload: dict[str, Any] = {
            "name": self.name,
            "run_type": self.run_type,
            "inputs": dict(self.inputs),
            "outputs": dict(self.outputs),
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "trace_context": self.trace_context.to_dict(),
            "guard_evidence": [dict(e) for e in self.guard_evidence],
            "cost_metadata": dict(self.cost_metadata),
        }
        if self.start_time is not None:
            payload["start_time"] = self.start_time
        if self.end_time is not None:
            payload["end_time"] = self.end_time
        if self.error is not None:
            payload["error"] = self.error
        return payload


class ReceiptEnricher:
    """Transform Chio receipts into platform-agnostic :class:`SpanPayload`.

    Parameters
    ----------
    default_tags:
        Tags applied to every span regardless of receipt contents. Use
        this to stamp a deployment environment (``env:prod``) or
        service label (``service:kernel``) onto every published span.
    include_parameters:
        When ``True`` (the default), copy the receipt's action
        parameters into the span ``inputs``. Disable for environments
        where tool parameters may contain sensitive payloads; the
        parameter hash is always preserved in ``metadata``.
    truncate_parameters:
        If set to a positive integer, stringify ``inputs`` values that
        serialise to more than N bytes and replace them with a
        ``{"truncated": True, "length": N}`` marker. Useful to keep
        LangSmith/LangFuse payloads under per-platform limits.
    """

    def __init__(
        self,
        *,
        default_tags: list[str] | None = None,
        include_parameters: bool = True,
        truncate_parameters: int | None = None,
    ) -> None:
        self._default_tags = list(default_tags or [])
        self._include_parameters = include_parameters
        self._truncate_parameters = truncate_parameters

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(
        self,
        receipt: ChioReceipt,
        *,
        tool_result: Any | None = None,
        error: str | None = None,
    ) -> SpanPayload:
        """Build a :class:`SpanPayload` from a Chio receipt.

        Parameters
        ----------
        receipt:
            The signed receipt returned by the kernel.
        tool_result:
            Optional tool-side result to attach as ``outputs.result``.
            The Chio receipt itself never carries the tool's output; the
            caller supplies it when publishing post-execution spans.
        error:
            Optional error message to attach to the span (surfaced as
            ``payload.error`` for bridges that expose error fields).
        """
        metadata_obj = receipt.metadata or {}
        trace_context = self._extract_trace_context(metadata_obj)
        cost_metadata = self._extract_cost_metadata(metadata_obj)

        inputs = self._build_inputs(receipt)
        outputs = self._build_outputs(receipt, tool_result=tool_result)

        tags = self._build_tags(receipt, cost_metadata=cost_metadata)
        metadata = self._build_metadata(
            receipt,
            cost_metadata=cost_metadata,
            trace_context=trace_context,
        )

        guard_evidence = [self._evidence_to_dict(e) for e in receipt.evidence]

        start_time, end_time = self._timing_from_metadata(metadata_obj, receipt.timestamp)

        return SpanPayload(
            name=receipt.tool_name,
            run_type="tool",
            inputs=inputs,
            outputs=outputs,
            tags=tags,
            metadata=metadata,
            trace_context=trace_context,
            start_time=start_time,
            end_time=end_time,
            error=error,
            cost_metadata=cost_metadata,
            guard_evidence=guard_evidence,
        )

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_inputs(self, receipt: ChioReceipt) -> dict[str, Any]:
        if not self._include_parameters:
            return {}
        params = dict(receipt.action.parameters)
        if self._truncate_parameters is not None:
            limit = self._truncate_parameters
            for key, value in list(params.items()):
                rendered = repr(value)
                if len(rendered) > limit:
                    params[key] = {"truncated": True, "length": len(rendered)}
        return params

    def _build_outputs(
        self,
        receipt: ChioReceipt,
        *,
        tool_result: Any | None,
    ) -> dict[str, Any]:
        decision = receipt.decision
        outputs: dict[str, Any] = {
            "receipt_kind": getattr(receipt, "receipt_kind", None),
            "boundary_class": getattr(receipt, "boundary_class", None),
        }
        if decision is not None:
            outputs["decision"] = {
                "verdict": decision.verdict,
            }
            if decision.reason is not None:
                outputs["decision"]["reason"] = decision.reason
            if decision.guard is not None:
                outputs["decision"]["guard"] = decision.guard
        if receipt.evidence:
            outputs["evidence"] = [self._evidence_to_dict(e) for e in receipt.evidence]
        if tool_result is not None:
            outputs["result"] = tool_result
        return outputs

    def _build_tags(
        self,
        receipt: ChioReceipt,
        *,
        cost_metadata: dict[str, Any],
    ) -> list[str]:
        tags: list[str] = list(self._default_tags)
        decision = receipt.decision
        tags.append(f"chio.verdict:{decision.verdict if decision is not None else 'none'}")
        if getattr(receipt, "receipt_kind", None) is not None:
            tags.append(f"chio.receipt_kind:{receipt.receipt_kind}")
        if getattr(receipt, "boundary_class", None) is not None:
            tags.append(f"chio.boundary_class:{receipt.boundary_class}")
        if getattr(receipt, "trust_level", None) is not None:
            tags.append(f"chio.trust_level:{receipt.trust_level}")
        tags.append(f"chio.tool:{receipt.tool_name}")
        tags.append(f"chio.server:{receipt.tool_server}")
        if decision is not None and decision.guard:
            tags.append(f"chio.guard:{decision.guard}")
        for evidence in receipt.evidence:
            # Guard evidence may list multiple guards; add each as a tag.
            tags.append(
                f"chio.evidence:{evidence.guard_name}:"
                f"{'allow' if evidence.verdict else 'deny'}"
            )
        currency = cost_metadata.get("currency")
        units = cost_metadata.get("units")
        if currency is not None and units is not None:
            tags.append(f"chio.cost:{units}{currency}")
        # Deduplicate while preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for tag in tags:
            if tag not in seen:
                seen.add(tag)
                unique.append(tag)
        return unique

    def _build_metadata(
        self,
        receipt: ChioReceipt,
        *,
        cost_metadata: dict[str, Any],
        trace_context: TraceContext,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "chio.receipt_id": receipt.id,
            "chio.capability_id": receipt.capability_id,
            "chio.tool_name": receipt.tool_name,
            "chio.tool_server": receipt.tool_server,
            "chio.verdict": receipt.decision.verdict if receipt.decision is not None else "none",
            "chio.receipt_kind": getattr(receipt, "receipt_kind", None),
            "chio.boundary_class": getattr(receipt, "boundary_class", None),
            "chio.trust_level": getattr(receipt, "trust_level", None),
            "chio.timestamp": receipt.timestamp,
            "chio.content_hash": receipt.content_hash,
            "chio.policy_hash": receipt.policy_hash,
            "chio.kernel_key": receipt.kernel_key,
            "chio.parameter_hash": receipt.action.parameter_hash,
        }
        if receipt.decision is not None and receipt.decision.reason is not None:
            metadata["chio.reason"] = receipt.decision.reason
        if receipt.decision is not None and receipt.decision.guard is not None:
            metadata["chio.guard"] = receipt.decision.guard
        if cost_metadata:
            metadata["chio.cost"] = dict(cost_metadata)
        if not trace_context.is_empty():
            metadata["chio.trace_context"] = trace_context.to_dict()
        # Preserve any additional metadata the kernel attached (except
        # the trace block we already flattened and the cost block).
        for key, value in (receipt.metadata or {}).items():
            if key in ("trace", "cost"):
                continue
            metadata[f"chio.extra.{key}"] = value
        return metadata

    @staticmethod
    def _evidence_to_dict(evidence: GuardEvidence) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "guard_name": evidence.guard_name,
            "verdict": "allow" if evidence.verdict else "deny",
        }
        if evidence.details is not None:
            payload["details"] = evidence.details
        return payload

    @staticmethod
    def _extract_trace_context(metadata: dict[str, Any]) -> TraceContext:
        trace_block = metadata.get("trace")
        if not isinstance(trace_block, dict):
            return TraceContext()
        return TraceContext(
            langsmith_run_id=_coerce_optional_str(trace_block.get("langsmith_run_id")),
            langsmith_parent_run_id=_coerce_optional_str(
                trace_block.get("langsmith_parent_run_id")
            ),
            langsmith_trace_id=_coerce_optional_str(trace_block.get("langsmith_trace_id")),
            langfuse_trace_id=_coerce_optional_str(trace_block.get("langfuse_trace_id")),
            langfuse_parent_observation_id=_coerce_optional_str(
                trace_block.get("langfuse_parent_observation_id")
            ),
        )

    @staticmethod
    def _extract_cost_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
        cost = metadata.get("cost")
        if isinstance(cost, MonetaryAmount):
            return {"units": cost.units, "currency": cost.currency}
        if isinstance(cost, dict):
            payload: dict[str, Any] = {}
            units = cost.get("units")
            currency = cost.get("currency")
            if isinstance(units, int):
                payload["units"] = units
            if isinstance(currency, str):
                payload["currency"] = currency
            # Pass-through any other fields the kernel attached.
            for key, value in cost.items():
                if key in ("units", "currency"):
                    continue
                payload[key] = value
            return payload
        return {}

    @staticmethod
    def _timing_from_metadata(
        metadata: dict[str, Any],
        fallback_timestamp: int,
    ) -> tuple[int | None, int | None]:
        timing = metadata.get("timing")
        if not isinstance(timing, dict):
            return (fallback_timestamp, fallback_timestamp)
        start = timing.get("started_at")
        end = timing.get("completed_at")
        start_value = start if isinstance(start, int) else fallback_timestamp
        end_value = end if isinstance(end, int) else fallback_timestamp
        return (start_value, end_value)


def _coerce_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


__all__ = [
    "ReceiptEnricher",
    "SpanPayload",
    "TraceContext",
]
