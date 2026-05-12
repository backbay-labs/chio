"""Chio-governed wrapper around Pulumi programs.

The :func:`chio_pulumi` decorator adapts the two-phase capability model
(``infra:plan`` / ``infra:apply``) to Pulumi's ``pulumi.Program``
abstraction. It is used in two complementary modes:

1. **Program gate** -- decorate a ``pulumi.Program`` (a zero-arg
   callable that registers resources) so that every preview / up that
   invokes the program first evaluates the Chio sidecar with the matching
   scope. Pulumi's preview maps to ``infra:plan``; up / apply maps to
   ``infra:apply``.

2. **Resource reviewer** -- when the decorator runs in ``apply`` mode it
   invokes the wrapped program in a "collection" pass that records the
   resource types it would register without actually creating them,
   then runs the :class:`PlanReviewGuard` against that collection. This
   lets Pulumi programs participate in the same plan-review flow the
   Terraform wrapper uses, even though Pulumi does not emit a plan JSON
   file by default.

The decorator is deliberately agnostic about how Pulumi is orchestrated
-- callers can wire it into ``pulumi automation`` (``pulumi.automation``
Python SDK), a raw ``pulumi up`` subprocess, or a test harness. The
only contract is that Pulumi eventually calls the decorated program.

Pulumi is an *optional* dependency (``chio-iac[pulumi]`` extra). When
Pulumi is not installed, the decorator still works for plan / review
purposes; only the resource-registration shim requires the
:mod:`pulumi` package.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast, overload

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt

from chio_iac.errors import ChioIACConfigError, ChioIACError
from chio_iac.plan_review import (
    PlanResource,
    PlanReviewGuard,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
)

ChioClientLike = Any
F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Phase selector
# ---------------------------------------------------------------------------


#: Valid phase strings. ``"plan"`` evaluates ``infra:plan`` and invokes
#: the program in a collection pass that records resource types without
#: registering them. ``"apply"`` evaluates ``infra:apply`` (after a
#: plan-review pass) and then invokes the program normally so Pulumi
#: registers resources.
_PHASES: frozenset[str] = frozenset({"plan", "apply"})

_PHASE_SCOPE: dict[str, str] = {
    "plan": "infra:plan",
    "apply": "infra:apply",
}

_PHASE_TOOL_NAME: dict[str, str] = {
    "plan": "pulumi:preview",
    "apply": "pulumi:up",
}


# ---------------------------------------------------------------------------
# Resource collection context
# ---------------------------------------------------------------------------


@dataclass
class _CollectedResource:
    """A resource type recorded during a plan-phase collection pass."""

    resource_type: str
    name: str = ""
    action: str = "create"


@dataclass
class _PulumiContext:
    """Per-program-invocation state exposed to the collection shim."""

    phase: str
    collected: list[_CollectedResource] = field(default_factory=list)


_current_context: ContextVar[_PulumiContext | None] = ContextVar(
    "chio_iac_pulumi_context", default=None
)


def _current_pulumi_context() -> _PulumiContext | None:
    """Return the active :class:`_PulumiContext` (or ``None``)."""
    return _current_context.get()


def record_resource(
    resource_type: str,
    *,
    name: str = "",
    action: str = "create",
) -> None:
    """Record a resource the decorated program would register.

    Pulumi programs can call this explicitly when they want to
    participate in Chio's plan-review pass without relying on the
    automatic :mod:`pulumi` shim. The call is a no-op outside an
    :func:`chio_pulumi` ``plan`` invocation.

    Parameters
    ----------
    resource_type:
        The Pulumi resource type token (e.g. ``aws:rds/instance:Instance``
        or ``kubernetes:apps/v1:Deployment``). The plan-review guard
        matches against this string.
    name:
        Optional Pulumi logical name -- surfaced on deny violations so
        operators can identify which resource was out of scope.
    action:
        One of ``create``, ``update``, ``delete``, ``replace``. Defaults
        to ``create`` for new-resource programs.
    """
    ctx = _current_context.get()
    if ctx is None:
        return
    ctx.collected.append(
        _CollectedResource(
            resource_type=resource_type,
            name=name,
            action=action,
        )
    )


# ---------------------------------------------------------------------------
# Sidecar evaluation
# ---------------------------------------------------------------------------


async def _evaluate_sidecar(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    phase: str,
    parameters: dict[str, Any],
    redaction_policy: RedactionPolicy,
) -> ChioReceipt:
    """Evaluate the sidecar and translate denies into :class:`ChioIACError`."""
    redacted_parameters = redact_args(
        tool_name, parameters, policy=redaction_policy
    )
    try:
        receipt = await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=redacted_parameters,
        )
    except ChioDeniedError as exc:
        raise ChioIACError(
            f"Chio denied pulumi {phase}: {exc.reason or exc.message}",
            subcommand=phase,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            guard=exc.guard,
            reason=exc.reason or exc.message,
            receipt_id=exc.receipt_id,
        ) from exc

    if receipt.is_denied:
        decision = receipt.decision
        raise ChioIACError(
            f"Chio denied pulumi {phase}: {decision.reason or 'denied by Chio kernel'}",
            subcommand=phase,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            guard=decision.guard,
            reason=decision.reason,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )

    return receipt


# ---------------------------------------------------------------------------
# @chio_pulumi decorator
# ---------------------------------------------------------------------------


@overload
def chio_pulumi(
    __fn: F,
) -> F: ...


@overload
def chio_pulumi(
    *,
    capability_id: str,
    phase: str = "apply",
    tool_server: str = "pulumi",
    plan_review_guard: PlanReviewGuard | None = None,
    allowlist: ResourceTypeAllowlist | None = None,
    denylist: ResourceTypeDenylist | None = None,
    allow_destroy: bool | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> Callable[[F], F]: ...


def chio_pulumi(
    __fn: F | None = None,
    *,
    capability_id: str | None = None,
    phase: str = "apply",
    tool_server: str = "pulumi",
    plan_review_guard: PlanReviewGuard | None = None,
    allowlist: ResourceTypeAllowlist | None = None,
    denylist: ResourceTypeDenylist | None = None,
    allow_destroy: bool | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    redaction_policy: RedactionPolicy | None = None,
) -> Any:
    """Decorator that gates a Pulumi program on an Chio capability.

    The decorated program is invoked exactly as Pulumi expects: as a
    zero-arg (or keyword-only) callable that registers resources. The
    difference is that the wrapper first evaluates the Chio sidecar for
    the configured ``phase`` and, on the ``apply`` phase, runs a
    :class:`PlanReviewGuard` against the resource types the program
    would register. Only after the plan passes review and the sidecar
    allows does the program run through to Pulumi for real.

    Parameters
    ----------
    capability_id:
        Required. Pre-minted capability token id.
    phase:
        ``"plan"`` evaluates ``infra:plan``; ``"apply"`` evaluates
        ``infra:apply`` and runs plan-review. Defaults to ``"apply"``.
    tool_server:
        Chio tool-server id for the sidecar evaluation. Defaults to
        ``"pulumi"``.
    plan_review_guard / allowlist / denylist / allow_destroy:
        Same as :func:`chio_iac.terraform.run_terraform`. Ignored on the
        ``plan`` phase (plan-review only runs before apply).
    chio_client / sidecar_url:
        Injection points for tests and custom transports.
    redaction_policy:
        Optional :class:`RedactionPolicy` applied to the parameters
        dict before it is forwarded to the sidecar. Defaults to
        :meth:`RedactionPolicy.chio_default`.

    Examples
    --------

    Guarding an apply:

    .. code-block:: python

        from chio_iac import chio_pulumi
        from chio_iac.plan_review import ResourceTypeAllowlist

        @chio_pulumi(
            capability_id="cap-42",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
        )
        def program():
            import pulumi_aws as aws
            aws.rds.Instance("db", engine="postgres", instance_class="db.t3.small")
    """

    def decorator(fn: F) -> F:
        if not capability_id:
            raise ChioIACConfigError(
                "chio_pulumi requires a non-empty capability_id"
            )
        if phase not in _PHASES:
            raise ChioIACConfigError(
                f"chio_pulumi phase must be one of {sorted(_PHASES)}; got {phase!r}"
            )

        guard = _resolve_guard(
            phase=phase,
            plan_review_guard=plan_review_guard,
            allowlist=allowlist,
            denylist=denylist,
            allow_destroy=allow_destroy,
        )
        effective_redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            async def async_body(*args: Any, **kwargs: Any) -> Any:
                return await _invoke_pulumi(
                    fn=fn,
                    args=args,
                    kwargs=kwargs,
                    capability_id=capability_id,
                    phase=phase,
                    tool_server=tool_server,
                    guard=guard,
                    chio_client_override=chio_client,
                    sidecar_url_override=sidecar_url,
                    is_async=True,
                    redaction_policy=effective_redaction_policy,
                )

            return cast(F, async_body)

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(
                _invoke_pulumi(
                    fn=fn,
                    args=args,
                    kwargs=kwargs,
                    capability_id=capability_id,
                    phase=phase,
                    tool_server=tool_server,
                    guard=guard,
                    chio_client_override=chio_client,
                    sidecar_url_override=sidecar_url,
                    is_async=False,
                    redaction_policy=effective_redaction_policy,
                )
            )

        return cast(F, sync_body)

    if __fn is not None:
        return decorator(__fn)
    return decorator


def _resolve_guard(
    *,
    phase: str,
    plan_review_guard: PlanReviewGuard | None,
    allowlist: ResourceTypeAllowlist | None,
    denylist: ResourceTypeDenylist | None,
    allow_destroy: bool | None,
) -> PlanReviewGuard | None:
    """Materialise the plan-review guard for the apply phase (if any)."""
    if phase != "apply":
        return None
    if plan_review_guard is not None:
        return plan_review_guard
    if allowlist is None and denylist is None and allow_destroy is None:
        # Apply phase without a guard is permitted when the program has
        # no collected resources (the kernel then gets full say). We
        # return None here and the invoke path degrades gracefully.
        return None
    return PlanReviewGuard(
        allowlist=allowlist or ResourceTypeAllowlist(),
        denylist=denylist or ResourceTypeDenylist(),
        allow_destroy=allow_destroy if allow_destroy is not None else False,
    )


async def _invoke_pulumi(
    *,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    capability_id: str,
    phase: str,
    tool_server: str,
    guard: PlanReviewGuard | None,
    chio_client_override: ChioClientLike | None,
    sidecar_url_override: str | None,
    is_async: bool,
    redaction_policy: RedactionPolicy,
) -> Any:
    """Shared sync / async implementation for :func:`chio_pulumi`."""
    scope_label = _PHASE_SCOPE[phase]
    tool_name = _PHASE_TOOL_NAME[phase]

    owner = _ChioClientOwner(
        client=chio_client_override,
        sidecar_url=sidecar_url_override,
    )
    try:
        client = owner.get()

        # ------------------------------------------------------------------
        # Plan-review pass (apply only): invoke the program with
        # resource-recording enabled to learn which resource types it
        # would register, then run the guard.
        # ------------------------------------------------------------------
        resource_types: list[str] = []
        if phase == "apply" and guard is not None:
            collected = await _collect_resources(fn, args, kwargs, is_async)
            plan_payload = _collected_to_plan(collected)
            verdict = guard.review(plan_payload)
            resource_types = sorted(
                {r.resource_type for r in verdict.resources if r.is_mutating}
            )
            verdict.raise_for_violations(
                subcommand=phase,
                capability_id=capability_id,
            )

        # ------------------------------------------------------------------
        # Sidecar evaluation.
        # ------------------------------------------------------------------
        await _evaluate_sidecar(
            chio_client=client,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            phase=phase,
            parameters={
                "phase": phase,
                "scope_label": scope_label,
                "resource_types": resource_types,
                "program": getattr(fn, "__name__", "<anonymous>"),
            },
            redaction_policy=redaction_policy,
        )
    finally:
        await owner.close()

    # ------------------------------------------------------------------
    # Allow path: run the program normally so Pulumi registers resources.
    # ------------------------------------------------------------------
    if is_async:
        return await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
    return await asyncio.to_thread(fn, *args, **kwargs)


async def _collect_resources(
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    is_async: bool,
) -> list[_CollectedResource]:
    """Invoke ``fn`` in collection mode and return the recorded resources.

    The collection mode is best-effort: Pulumi programs that do not call
    :func:`record_resource` explicitly will yield an empty list, which
    the plan-review guard interprets as "no resources to review" (i.e.
    the review step is a no-op). Programs that *do* call
    :func:`record_resource` -- either directly or through an integration
    layer -- get first-class plan-review.

    Exceptions raised by the program during collection are re-raised
    verbatim so configuration errors surface the same way they would
    during a real Pulumi run.
    """
    ctx = _PulumiContext(phase="plan")
    token = _current_context.set(ctx)
    try:
        if is_async:
            await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
        else:
            await asyncio.to_thread(fn, *args, **kwargs)
    finally:
        _current_context.reset(token)
    return list(ctx.collected)


def _collected_to_plan(
    collected: list[_CollectedResource],
) -> dict[str, Any]:
    """Convert collected resources into the plan shape the guard expects."""
    return {
        "resources": [
            {
                "type": r.resource_type,
                "name": r.name,
                "action": r.action,
            }
            for r in collected
        ]
    }


# ---------------------------------------------------------------------------
# ChioClient ownership helper
# ---------------------------------------------------------------------------


class _ChioClientOwner:
    """Own a lazily-constructed :class:`ChioClient` for one decorator call."""

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(
        self,
        *,
        client: ChioClientLike | None,
        sidecar_url: str | None,
    ) -> None:
        self._client = client
        self._owns = client is None
        self._sidecar_url = sidecar_url or ChioClient.DEFAULT_BASE_URL

    def get(self) -> ChioClientLike:
        if self._client is None:
            self._client = ChioClient(self._sidecar_url)
        return self._client

    async def close(self) -> None:
        if self._owns and self._client is not None:
            try:
                await self._client.close()
            except ChioError:
                pass
            finally:
                self._client = None


__all__ = [
    "ChioClientLike",
    "PlanResource",
    "chio_pulumi",
    "record_resource",
]
