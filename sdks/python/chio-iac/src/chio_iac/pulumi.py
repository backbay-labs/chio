"""Chio-governed wrapper around Pulumi programs.

:func:`chio_pulumi` adapts the two-phase capability model
(``infra:plan`` / ``infra:apply``) to a Pulumi program. On ``apply`` it
first runs the program in a recording pass (via :func:`record_resource`
or the optional ``pulumi`` shim), executes :class:`PlanReviewGuard`,
then evaluates the sidecar before invoking the program for real.
``pulumi`` is an optional extra; the decorator works without it for
plan / review.
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


_PHASES: frozenset[str] = frozenset({"plan", "apply"})

_PHASE_SCOPE: dict[str, str] = {
    "plan": "infra:plan",
    "apply": "infra:apply",
}

_PHASE_TOOL_NAME: dict[str, str] = {
    "plan": "pulumi:preview",
    "apply": "pulumi:up",
}


@dataclass
class _CollectedResource:
    resource_type: str
    name: str = ""
    action: str = "create"


@dataclass
class _PulumiContext:
    phase: str
    collected: list[_CollectedResource] = field(default_factory=list)


_current_context: ContextVar[_PulumiContext | None] = ContextVar(
    "chio_iac_pulumi_context", default=None
)


def _current_pulumi_context() -> _PulumiContext | None:
    return _current_context.get()


def record_resource(
    resource_type: str,
    *,
    name: str = "",
    action: str = "create",
) -> None:
    """Record a resource the decorated program would register (no-op outside ``plan``).

    ``resource_type`` is the Pulumi type token (e.g.
    ``aws:rds/instance:Instance``) the plan-review guard matches on.
    ``action`` is one of ``create``, ``update``, ``delete``, ``replace``.
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
    """Sidecar evaluate; translate both deny paths to :class:`ChioIACError`."""
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

    if not receipt.is_allowed:
        decision = receipt.decision
        raise ChioIACError(
            f"Chio denied pulumi {phase}: "
            f"{decision.reason if decision is not None and decision.reason is not None else 'non-authorizing Chio receipt'}",
            subcommand=phase,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            guard=decision.guard if decision is not None else None,
            reason=decision.reason if decision is not None else None,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True)
            if decision is not None
            else None,
        )

    return receipt


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
    """Gate a Pulumi program on a Chio capability.

    ``phase="plan"`` evaluates ``infra:plan``; ``"apply"`` evaluates
    ``infra:apply`` after a plan-review pass. ``plan_review_guard`` /
    ``allowlist`` / ``denylist`` / ``allow_destroy`` mirror
    :func:`chio_iac.terraform.run_terraform`; they are ignored on
    ``plan``.

    ``redaction_policy`` defaults to :meth:`RedactionPolicy.chio_default`;
    pass a custom policy to redact additional fields before the sidecar
    sees them. For example, to redact the program identifier on apply::

        from chio_adapter_base.redact import RedactionPolicy

        @chio_pulumi(
            capability_id="cap-pulumi",
            phase="apply",
            redaction_policy=RedactionPolicy({"pulumi:up": ("program",)}),
        )
        async def my_program() -> None:
            ...

    Note that a custom policy fully replaces (does not merge with) the
    chio default.
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
    if phase != "apply":
        return None
    if plan_review_guard is not None:
        return plan_review_guard
    if allowlist is None and denylist is None and allow_destroy is None:
        # No guard configured: kernel gets full say.
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
    scope_label = _PHASE_SCOPE[phase]
    tool_name = _PHASE_TOOL_NAME[phase]

    owner = _ChioClientOwner(
        client=chio_client_override,
        sidecar_url=sidecar_url_override,
    )
    try:
        client = owner.get()

        # Plan-review (apply only): collection pass, then guard.
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

    # Allow: run the program normally so Pulumi registers resources.
    if is_async:
        return await cast(Callable[..., Awaitable[Any]], fn)(*args, **kwargs)
    return await asyncio.to_thread(fn, *args, **kwargs)


async def _collect_resources(
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    is_async: bool,
) -> list[_CollectedResource]:
    """Invoke ``fn`` in collection mode; an empty list is "no resources to review"."""
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


class _ChioClientOwner:
    """Lazy :class:`ChioClient` owner; only closes clients it created itself."""

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
