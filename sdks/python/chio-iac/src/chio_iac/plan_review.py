"""Plan-review guard for Terraform and Pulumi IaC governance.

The plan-review guard is the second phase of the two-phase capability
model: ``terraform plan`` (``infra:plan`` scope) emits a plan file; this
guard parses the plan (via ``terraform show -json``) and denies
``terraform apply`` when the plan contains resource types outside the
granted scope.

The guard is intentionally simple and deterministic:

1. Parse the plan JSON into a list of ``(resource_type, change_action)``
   entries. Both Terraform (``resource_changes[*].type``) and Pulumi
   (``resources[*].type`` / ``steps[*].newState.type``) layouts are
   supported.
2. Consult a :class:`ResourceTypeAllowlist` + :class:`ResourceTypeDenylist`
   pair. The denylist wins on conflict (denylist is always applied first).
3. Any resource type not matched by the allowlist is denied. The
   allowlist may contain exact types (``aws_db_instance``) or glob
   prefixes (``aws_*``).
4. Emit a :class:`PlanReviewVerdict` -- ``allowed`` when zero violations,
   otherwise ``denied`` with the full violation list so the caller can
   surface every out-of-scope resource in one pass.

The guard does not talk to the sidecar; it is a pure-Python check the
Terraform / Pulumi wrappers run *before* dispatching the
``infra:apply``-scoped sidecar evaluation. The kernel still has the
final say; this guard is the local enforcement hook the two-phase model
needs to parse plan output (the sidecar does not read plan files).
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from chio_iac.errors import ChioIACConfigError, ChioIACPlanReviewError

# ---------------------------------------------------------------------------
# Allowlist / Denylist
# ---------------------------------------------------------------------------


class ResourceTypeAllowlist(BaseModel):
    """Resource types the apply capability is permitted to create or mutate.

    Entries may be exact resource type names (``aws_db_instance``) or
    :mod:`fnmatch` glob patterns (``aws_*``, ``kubernetes_*_v1``). The
    allowlist is inclusive -- anything not matched is out of scope.

    An empty allowlist denies everything (fail-closed). Pass
    ``patterns=["*"]`` to permit all resource types, which is useful for
    administrative capabilities that should bypass allowlist review.
    """

    patterns: list[str] = Field(default_factory=list)

    def matches(self, resource_type: str) -> bool:
        """Return ``True`` when ``resource_type`` matches any allowlist entry."""
        return any(_glob_match(resource_type, p) for p in self.patterns)


class ResourceTypeDenylist(BaseModel):
    """Resource types the apply capability is explicitly forbidden to touch.

    The denylist is applied *before* the allowlist -- a resource type on
    the denylist is rejected even when the allowlist would otherwise
    permit it. This lets operators grant ``aws_*`` broadly and then
    carve out ``aws_iam_*`` for a separate, tighter capability.

    An empty denylist never denies anything on its own; allowlist
    matching still gates which resource types may be applied.
    """

    patterns: list[str] = Field(default_factory=list)

    def matches(self, resource_type: str) -> bool:
        """Return ``True`` when ``resource_type`` matches any denylist entry."""
        return any(_glob_match(resource_type, p) for p in self.patterns)


def _glob_match(resource_type: str, pattern: str) -> bool:
    """Case-insensitive glob match for resource type names.

    Terraform resource types are lowercase by convention but we
    normalise so operators can write patterns in either case.
    """
    return fnmatch.fnmatchcase(resource_type.lower(), pattern.lower())


# ---------------------------------------------------------------------------
# Plan resource / verdict structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanResource:
    """A single resource change extracted from a plan file.

    ``action`` is one of the Terraform change-kind strings: ``create``,
    ``update``, ``delete``, ``no-op``, ``read``, ``replace``. For Pulumi
    plans the mapping is: ``create`` / ``update`` / ``delete`` /
    ``same`` / ``read`` / ``replace``. ``no-op`` / ``same`` / ``read``
    resources never trigger denial -- they do not mutate the cloud.
    """

    resource_type: str
    address: str
    action: str

    @property
    def is_mutating(self) -> bool:
        """True when this change actually modifies the cloud."""
        return self.action not in {"no-op", "same", "read"}


@dataclass
class PlanReviewVerdict:
    """Result of a :meth:`PlanReviewGuard.review` call.

    When ``allowed`` is ``False`` the ``violations`` list contains one
    entry per denied resource, each with the resource type, address, the
    action that would have been taken, and a human-readable reason.
    """

    allowed: bool
    resources: list[PlanResource] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)

    def raise_for_violations(
        self,
        *,
        subcommand: str = "apply",
        capability_id: str | None = None,
    ) -> None:
        """Raise :class:`ChioIACPlanReviewError` when the plan is denied.

        Call this after :meth:`PlanReviewGuard.review` to surface a
        deny-all summary with every out-of-scope resource. When the plan
        is allowed this is a no-op.
        """
        if self.allowed:
            return
        summary = ", ".join(
            sorted({str(v["resource_type"]) for v in self.violations})
        )
        raise ChioIACPlanReviewError(
            f"plan contains out-of-scope resource types: {summary}",
            violations=self.violations,
            subcommand=subcommand,
            capability_id=capability_id,
        )


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


class PlanReviewGuard:
    """Parses an IaC plan and denies out-of-scope resource types.

    Parameters
    ----------
    allowlist:
        :class:`ResourceTypeAllowlist` enumerating permitted resource
        types (exact names or glob patterns). Empty allowlist denies
        everything; use ``ResourceTypeAllowlist(patterns=["*"])`` to
        permit every resource type.
    denylist:
        Optional :class:`ResourceTypeDenylist` applied before the
        allowlist. A resource on the denylist is rejected even when the
        allowlist would permit it.
    allow_destroy:
        When ``False`` (the default), any ``delete`` action triggers a
        violation regardless of allowlist membership. Destroy actions
        are the highest-blast-radius change and should require an
        explicit opt-in. Set to ``True`` when the capability is expected
        to manage full resource lifecycles including teardown.

    Usage
    -----

    .. code-block:: python

        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*", "aws_elasticache_*"]),
            denylist=ResourceTypeDenylist(patterns=["aws_iam_*"]),
        )
        verdict = guard.review_file("tfplan.json")
        verdict.raise_for_violations(subcommand="apply", capability_id="cap-42")
    """

    def __init__(
        self,
        *,
        allowlist: ResourceTypeAllowlist | None = None,
        denylist: ResourceTypeDenylist | None = None,
        allow_destroy: bool = False,
    ) -> None:
        self.allowlist = allowlist or ResourceTypeAllowlist()
        self.denylist = denylist or ResourceTypeDenylist()
        self.allow_destroy = allow_destroy

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def review(self, plan: dict[str, Any]) -> PlanReviewVerdict:
        """Review a parsed plan JSON dict.

        Accepts both Terraform (``terraform show -json``) and Pulumi
        (``pulumi preview --json``) plan shapes. Returns a
        :class:`PlanReviewVerdict`; call :meth:`PlanReviewVerdict.raise_for_violations`
        to surface a deny error.
        """
        resources = _extract_resources(plan)
        violations: list[dict[str, Any]] = []

        if not resources and not _has_recognized_plan_shape(plan):
            violations.append(
                {
                    "resource_type": "unknown",
                    "address": "<plan>",
                    "action": "unknown",
                    "reason": (
                        "plan JSON did not match Terraform resource_changes "
                        "or Pulumi steps/resources shape"
                    ),
                }
            )

        for resource in resources:
            if not resource.is_mutating:
                # ``no-op`` / ``read`` / ``same`` -- nothing to review.
                continue

            if not self.allow_destroy and resource.action in {"delete", "replace"}:
                # ``replace`` implies a destroy-then-create cycle, which
                # carries the same blast radius as a raw delete.
                violations.append(
                    {
                        "resource_type": resource.resource_type,
                        "address": resource.address,
                        "action": resource.action,
                        "reason": (
                            f"{resource.action!r} action denied: destroys are "
                            "disabled for this capability (pass allow_destroy=True "
                            "to permit)"
                        ),
                    }
                )
                continue

            if self.denylist.matches(resource.resource_type):
                violations.append(
                    {
                        "resource_type": resource.resource_type,
                        "address": resource.address,
                        "action": resource.action,
                        "reason": (
                            f"resource type {resource.resource_type!r} is on "
                            "the denylist"
                        ),
                    }
                )
                continue

            if not self.allowlist.matches(resource.resource_type):
                violations.append(
                    {
                        "resource_type": resource.resource_type,
                        "address": resource.address,
                        "action": resource.action,
                        "reason": (
                            f"resource type {resource.resource_type!r} is "
                            "not on the allowlist"
                        ),
                    }
                )

        return PlanReviewVerdict(
            allowed=not violations,
            resources=list(resources),
            violations=violations,
        )

    def review_file(self, path: str | Path) -> PlanReviewVerdict:
        """Review a plan JSON file on disk.

        The file must be the output of ``terraform show -json tfplan``
        or ``pulumi preview --json``. Raises :class:`ChioIACConfigError`
        when the file is missing or unparseable.
        """
        plan_path = Path(path)
        if not plan_path.exists():
            raise ChioIACConfigError(
                f"plan file {plan_path!s} does not exist"
            )
        try:
            raw = plan_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ChioIACConfigError(
                f"failed to read plan file {plan_path!s}: {exc}"
            ) from exc
        return self.review_json(raw)

    def review_json(self, plan_json: str | bytes) -> PlanReviewVerdict:
        """Review a JSON string or bytes payload of plan output."""
        try:
            plan = json.loads(plan_json)
        except json.JSONDecodeError as exc:
            raise ChioIACConfigError(
                f"plan payload is not valid JSON: {exc.msg} at line "
                f"{exc.lineno}, column {exc.colno}"
            ) from exc
        if not isinstance(plan, dict):
            raise ChioIACConfigError(
                "plan payload must be a JSON object (Terraform / Pulumi plan shape)"
            )
        return self.review(plan)

    def resource_types(self, plan: dict[str, Any]) -> list[str]:
        """Return the sorted set of mutating resource types in ``plan``.

        Convenience helper for CLI operators who want to list the types
        a plan touches without running the full allow/deny evaluation.
        """
        return sorted(
            {
                r.resource_type
                for r in _extract_resources(plan)
                if r.is_mutating
            }
        )


# ---------------------------------------------------------------------------
# Plan shape extraction
# ---------------------------------------------------------------------------


def _extract_resources(plan: dict[str, Any]) -> list[PlanResource]:
    """Best-effort extraction of ``(type, address, action)`` tuples from a plan.

    Supports three shapes:

    * Terraform ``show -json`` output: top-level ``resource_changes``
      list, each element has ``type``, ``address``, ``change.actions``.
    * Pulumi ``preview --json`` (steps variant): top-level ``steps``
      list, each element has ``op`` and ``newState.urn`` / ``type``.
    * Pulumi preview (simple variant): top-level ``resources`` list with
      ``type`` and ``action``.

    Unknown shapes yield an empty list; :meth:`PlanReviewGuard.review`
    converts that into a deny verdict unless the payload is a recognized
    empty Terraform / Pulumi plan.
    """
    # Terraform format
    resource_changes = plan.get("resource_changes")
    if isinstance(resource_changes, list):
        return [_from_terraform_change(c) for c in resource_changes if isinstance(c, dict)]

    # Pulumi "steps" format
    steps = plan.get("steps")
    if isinstance(steps, list):
        return [_from_pulumi_step(s) for s in steps if isinstance(s, dict)]

    # Pulumi flattened "resources" format
    resources = plan.get("resources")
    if isinstance(resources, list):
        return [_from_pulumi_resource(r) for r in resources if isinstance(r, dict)]

    return []


def _has_recognized_plan_shape(plan: dict[str, Any]) -> bool:
    return any(isinstance(plan.get(key), list) for key in ("resource_changes", "steps", "resources"))


def _from_terraform_change(change: dict[str, Any]) -> PlanResource:
    """Build a :class:`PlanResource` from a Terraform ``resource_changes`` entry."""
    resource_type = str(change.get("type", "unknown"))
    address = str(change.get("address", resource_type))
    change_block = change.get("change")
    action = "no-op"
    if isinstance(change_block, dict):
        actions = change_block.get("actions")
        if isinstance(actions, list) and actions:
            # Terraform uses a list so it can express create+delete for
            # a "replace". Collapse to the most destructive verb present.
            action = _collapse_terraform_actions([str(a) for a in actions])
    return PlanResource(
        resource_type=resource_type,
        address=address,
        action=action,
    )


def _collapse_terraform_actions(actions: list[str]) -> str:
    """Collapse a Terraform actions list into a single change kind."""
    if "delete" in actions and "create" in actions:
        return "replace"
    for candidate in ("delete", "replace", "create", "update", "read", "no-op"):
        if candidate in actions:
            return candidate
    return actions[0] if actions else "no-op"


def _from_pulumi_step(step: dict[str, Any]) -> PlanResource:
    """Build a :class:`PlanResource` from a Pulumi ``steps`` entry."""
    op = str(step.get("op", "same"))
    action = _PULUMI_OP_TO_ACTION.get(op, op)
    resource_type = "unknown"
    address = ""
    new_state = step.get("newState") or step.get("oldState")
    if isinstance(new_state, dict):
        resource_type = str(new_state.get("type", resource_type))
        address = str(new_state.get("urn", new_state.get("id", resource_type)))
    return PlanResource(
        resource_type=resource_type,
        address=address,
        action=action,
    )


def _from_pulumi_resource(resource: dict[str, Any]) -> PlanResource:
    """Build a :class:`PlanResource` from a flat Pulumi ``resources`` entry."""
    resource_type = str(resource.get("type", "unknown"))
    address = str(resource.get("urn", resource.get("name", resource_type)))
    action_raw = str(resource.get("action") or resource.get("op") or "same")
    action = _PULUMI_OP_TO_ACTION.get(action_raw, action_raw)
    return PlanResource(
        resource_type=resource_type,
        address=address,
        action=action,
    )


_PULUMI_OP_TO_ACTION: dict[str, str] = {
    "same": "no-op",
    "create": "create",
    "update": "update",
    "delete": "delete",
    "replace": "replace",
    "create-replacement": "replace",
    "delete-replaced": "replace",
    "read": "read",
    "import": "create",
    "refresh": "read",
}


__all__ = [
    "PlanResource",
    "PlanReviewGuard",
    "PlanReviewVerdict",
    "ResourceTypeAllowlist",
    "ResourceTypeDenylist",
]
