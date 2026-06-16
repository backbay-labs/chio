"""Workflow-level receipt aggregation for Chio-governed Temporal workflows.

On workflow completion (success or failure), :class:`WorkflowReceipt`
aggregates every per-activity :class:`chio_sdk.models.ChioReceipt` the
interceptor collected during the run. The aggregate is serialised to a
stable JSON envelope that the Chio receipt store can ingest.

The envelope layout (version ``chio-temporal/v1``) is intentionally
minimal and additive:

* ``workflow_id`` / ``run_id`` -- Temporal identifiers.
* ``parent_workflow_ids`` -- ordered list of ancestor workflow ids
  (empty for a root workflow).
* ``started_at`` / ``completed_at`` -- unix seconds; ``None`` when the
  workflow has not yet completed.
* ``outcome`` -- ``"success"``, ``"failure"``, ``"cancelled"``, or
  ``"in_progress"``.
* ``step_count`` -- number of per-activity receipts aggregated.
* ``allow_count`` / ``deny_count`` -- aggregate counts by decision
  verdict, useful for quick audit queries without reading every step.
* ``steps`` -- ordered list of per-activity entries, each carrying the
  activity type / id, the underlying Chio receipt (as-is), and the
  attempt number.
* ``metadata`` -- caller-supplied dict merged with the
  :class:`WorkflowGrant` metadata.

Serialisation uses :mod:`json.dumps` with sorted keys so downstream
Merkle chaining stays deterministic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from chio_sdk.models import ChioReceipt

from chio_temporal.errors import ChioTemporalConfigError

#: Envelope schema version. Bump on any breaking change to the
#: serialised layout so the receipt store can route old payloads.
ENVELOPE_VERSION = "chio-temporal/v1"


@dataclass
class WorkflowStepReceipt:
    """A single per-activity receipt captured during a workflow run.

    Parameters
    ----------
    activity_type:
        The Temporal activity type (the registered name). Matches
        ``temporalio.activity.Info.activity_type``.
    activity_id:
        The Temporal activity id (unique per workflow run). Matches
        ``temporalio.activity.Info.activity_id``.
    attempt:
        Temporal's retry attempt counter. ``1`` for the first execution.
    receipt:
        The :class:`ChioReceipt` returned by the Chio sidecar for this
        activity's capability evaluation.
    """

    activity_type: str
    activity_id: str
    attempt: int
    receipt: ChioReceipt

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of this step receipt."""
        return {
            "activity_type": self.activity_type,
            "activity_id": self.activity_id,
            "attempt": int(self.attempt),
            "receipt": self.receipt.model_dump(mode="json", exclude_none=True),
        }


@dataclass
class WorkflowReceipt:
    """Aggregate of every per-activity receipt in a Temporal workflow run.

    Instances are built incrementally as activities execute
    (:meth:`record_step`) and finalised once the workflow completes
    (:meth:`finalize`). :meth:`to_envelope` / :meth:`to_json` produce the
    ingest envelope for the Chio receipt store.

    Thread/async safety: callers must serialise :meth:`record_step` calls
    themselves (the interceptor does this implicitly because Temporal
    only calls one activity at a time per worker task, but if a
    receipt is threaded across coroutines, wrap the call site).
    """

    workflow_id: str
    run_id: str | None = None
    parent_workflow_ids: list[str] = field(default_factory=list)
    started_at: int | None = None
    completed_at: int | None = None
    outcome: str = "in_progress"
    steps: list[WorkflowStepReceipt] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    _ALLOWED_OUTCOMES = ("in_progress", "success", "failure", "cancelled")

    def __post_init__(self) -> None:
        if not self.workflow_id:
            raise ChioTemporalConfigError(
                "WorkflowReceipt.workflow_id must be a non-empty string"
            )
        if self.outcome not in self._ALLOWED_OUTCOMES:
            raise ChioTemporalConfigError(
                f"WorkflowReceipt.outcome must be one of {self._ALLOWED_OUTCOMES}; "
                f"got {self.outcome!r}"
            )

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------

    def record_step(
        self,
        *,
        activity_type: str,
        activity_id: str,
        attempt: int,
        receipt: ChioReceipt,
    ) -> WorkflowStepReceipt:
        """Append a per-activity receipt to the running workflow receipt.

        Returns the newly-appended :class:`WorkflowStepReceipt` so
        callers can mutate metadata on it if needed. Appends happen in
        call order; the interceptor calls this after each sidecar
        evaluation, so the final ``steps`` list mirrors the activity
        execution sequence.
        """
        if not activity_type:
            raise ChioTemporalConfigError(
                "record_step requires a non-empty activity_type"
            )
        step = WorkflowStepReceipt(
            activity_type=activity_type,
            activity_id=activity_id,
            attempt=int(attempt),
            receipt=receipt,
        )
        self.steps.append(step)
        return step

    def finalize(
        self,
        *,
        outcome: str,
        completed_at: int,
    ) -> None:
        """Mark the workflow complete and freeze its outcome.

        Idempotent: calling :meth:`finalize` a second time with a
        different outcome raises :class:`ChioTemporalConfigError` to
        surface accidental double-completion.
        """
        if outcome not in self._ALLOWED_OUTCOMES:
            raise ChioTemporalConfigError(
                f"outcome must be one of {self._ALLOWED_OUTCOMES}; got {outcome!r}"
            )
        if self.completed_at is not None and self.outcome != outcome:
            raise ChioTemporalConfigError(
                "WorkflowReceipt already finalised with a different outcome"
            )
        self.outcome = outcome
        self.completed_at = int(completed_at)

    # ------------------------------------------------------------------
    # Aggregate counts
    # ------------------------------------------------------------------

    @property
    def step_count(self) -> int:
        """Total number of per-activity receipts aggregated."""
        return len(self.steps)

    @property
    def allow_count(self) -> int:
        """Number of aggregated activities with an allow verdict."""
        return sum(1 for step in self.steps if step.receipt.is_allowed)

    @property
    def deny_count(self) -> int:
        """Number of aggregated activities with a deny verdict."""
        return sum(1 for step in self.steps if step.receipt.is_denied)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_envelope(self) -> dict[str, Any]:
        """Build the ingest envelope the Chio receipt store expects.

        The layout is stable across minor versions (see
        :data:`ENVELOPE_VERSION`).
        """
        return {
            "version": ENVELOPE_VERSION,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "parent_workflow_ids": list(self.parent_workflow_ids),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "step_count": self.step_count,
            "allow_count": self.allow_count,
            "deny_count": self.deny_count,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        """Serialise :meth:`to_envelope` to stable JSON (sorted keys)."""
        return json.dumps(
            self.to_envelope(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


__all__ = [
    "ENVELOPE_VERSION",
    "WorkflowReceipt",
    "WorkflowStepReceipt",
]
