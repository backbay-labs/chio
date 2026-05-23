"""Terraform CLI wrapper with two-phase Chio capability enforcement.

``infra:plan`` (low-privilege, read-only) gates ``terraform plan``;
``infra:apply`` (high-privilege, mutating) gates ``terraform apply`` /
``destroy`` after a :class:`PlanReviewGuard` parses the plan JSON. The
wrapper shells out to ``terraform``; tests mock ``_run_subprocess``.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt

from chio_iac.errors import ChioIACConfigError, ChioIACError
from chio_iac.plan_review import (
    PlanReviewGuard,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
)

# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any


_SUBCOMMAND_SCOPE: dict[str, str] = {
    "plan": "infra:plan",
    "apply": "infra:apply",
    "destroy": "infra:apply",
}

_TOOL_NAME_FOR: dict[str, str] = {
    "plan": "terraform:plan",
    "apply": "terraform:apply",
    "destroy": "terraform:destroy",
}

# Subcommands that require the plan-review guard before dispatch.
_APPLY_SUBCOMMANDS: frozenset[str] = frozenset({"apply", "destroy"})


@dataclass
class TerraformResult:
    """Allow-path return value of :func:`run_terraform`."""

    subcommand: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    command: list[str] = field(default_factory=list)
    receipt: ChioReceipt | None = None
    plan_path: str | None = None
    resource_types: list[str] = field(default_factory=list)


def _resolve_terraform_binary(override: str | None) -> str:
    """Locate ``terraform``: explicit override > ``$CHIO_IAC_TERRAFORM`` > ``$PATH``."""
    candidate = override or os.environ.get("CHIO_IAC_TERRAFORM")
    if candidate:
        resolved = shutil.which(candidate) or candidate
        if not Path(resolved).exists():
            raise ChioIACConfigError(
                f"terraform binary {candidate!r} was not found on PATH"
            )
        return resolved

    discovered = shutil.which("terraform")
    if discovered is None:
        raise ChioIACConfigError(
            "terraform binary not found on PATH; set $CHIO_IAC_TERRAFORM or "
            "pass terraform_binary= to run_terraform"
        )
    return discovered


def _run_subprocess(
    command: Sequence[str],
    *,
    cwd: str | Path | None,
    capture_output: bool,
    env: dict[str, str] | None,
) -> subprocess.CompletedProcess[str]:
    """Module-level subprocess wrapper so tests can monkey-patch it."""
    return subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=capture_output,
        text=True,
        env=env,
        check=False,
    )


async def _evaluate_sidecar(
    *,
    chio_client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    subcommand: str,
    parameters: dict[str, Any],
    redaction_policy: RedactionPolicy,
) -> ChioReceipt:
    """Call ``/v1/evaluate``; both deny paths raise :class:`ChioIACError`.

    Transport / kernel errors propagate as :class:`ChioError` so callers
    can retry without confusing them with policy denials.
    """
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
            f"Chio denied terraform {subcommand}: {exc.reason or exc.message}",
            subcommand=subcommand,
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
            f"Chio denied terraform {subcommand}: "
            f"{decision.reason if decision is not None and decision.reason is not None else 'non-authorizing Chio receipt'}",
            subcommand=subcommand,
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


async def run_terraform(
    subcommand: str,
    args: Sequence[str] | None = None,
    *,
    capability_id: str,
    tool_server: str = "terraform",
    working_dir: str | Path | None = None,
    plan_path: str | Path | None = None,
    plan_review_guard: PlanReviewGuard | None = None,
    allowlist: ResourceTypeAllowlist | None = None,
    denylist: ResourceTypeDenylist | None = None,
    allow_destroy: bool | None = None,
    chio_client: ChioClientLike | None = None,
    sidecar_url: str | None = None,
    terraform_binary: str | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
    redaction_policy: RedactionPolicy | None = None,
) -> TerraformResult:
    """Run ``terraform <subcommand>`` with Chio capability enforcement.

    ``plan`` evaluates ``infra:plan`` then runs ``terraform plan -out=tfplan``
    and writes a JSON dump to ``<plan_path>.json``. ``apply`` / ``destroy``
    load that JSON, run :class:`PlanReviewGuard`, evaluate ``infra:apply``,
    then dispatch. ``redaction_policy`` defaults to
    :meth:`RedactionPolicy.chio_default`.
    """
    if subcommand not in _SUBCOMMAND_SCOPE:
        raise ChioIACConfigError(
            f"unsupported terraform subcommand {subcommand!r}; "
            f"expected one of {sorted(_SUBCOMMAND_SCOPE)}"
        )
    if not capability_id:
        raise ChioIACConfigError(
            "run_terraform requires a non-empty capability_id"
        )

    resolved_binary = _resolve_terraform_binary(terraform_binary)
    resolved_cwd = Path(working_dir) if working_dir is not None else Path.cwd()
    resolved_plan_path = (
        Path(plan_path)
        if plan_path is not None
        else resolved_cwd / "tfplan"
    )
    tool_name = _TOOL_NAME_FOR[subcommand]
    scope_label = _SUBCOMMAND_SCOPE[subcommand]
    extra_args = list(args or [])
    resolved_env: dict[str, str] | None
    if env is not None:
        resolved_env = dict(os.environ)
        resolved_env.update(env)
    else:
        resolved_env = None

    guard = _resolve_plan_review_guard(
        subcommand,
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

    owner = _ChioClientOwner(client=chio_client, sidecar_url=sidecar_url)
    try:
        client = owner.get()
        if subcommand == "plan":
            return await _run_plan(
                client=client,
                capability_id=capability_id,
                tool_server=tool_server,
                tool_name=tool_name,
                scope_label=scope_label,
                working_dir=resolved_cwd,
                plan_path=resolved_plan_path,
                extra_args=extra_args,
                terraform_binary=resolved_binary,
                env=resolved_env,
                capture_output=capture_output,
                redaction_policy=effective_redaction_policy,
            )

        return await _run_apply_or_destroy(
            client=client,
            subcommand=subcommand,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            scope_label=scope_label,
            guard=guard,
            working_dir=resolved_cwd,
            plan_path=resolved_plan_path,
            extra_args=extra_args,
            terraform_binary=resolved_binary,
            env=resolved_env,
            capture_output=capture_output,
            redaction_policy=effective_redaction_policy,
        )
    finally:
        await owner.close()


def _resolve_plan_review_guard(
    subcommand: str,
    *,
    plan_review_guard: PlanReviewGuard | None,
    allowlist: ResourceTypeAllowlist | None,
    denylist: ResourceTypeDenylist | None,
    allow_destroy: bool | None,
) -> PlanReviewGuard | None:
    """Build the plan-review guard for apply-family subcommands."""
    if subcommand not in _APPLY_SUBCOMMANDS:
        return None
    if plan_review_guard is not None:
        return plan_review_guard
    if allowlist is None and denylist is None and allow_destroy is None:
        raise ChioIACConfigError(
            f"terraform {subcommand} requires a plan_review_guard "
            "(or an allowlist / denylist / allow_destroy shortcut) so "
            "out-of-scope resource types can be denied"
        )
    return PlanReviewGuard(
        allowlist=allowlist or ResourceTypeAllowlist(),
        denylist=denylist or ResourceTypeDenylist(),
        allow_destroy=(
            allow_destroy if allow_destroy is not None
            else (subcommand == "destroy")
        ),
    )


async def _run_plan(
    *,
    client: ChioClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    scope_label: str,
    working_dir: Path,
    plan_path: Path,
    extra_args: list[str],
    terraform_binary: str,
    env: dict[str, str] | None,
    capture_output: bool,
    redaction_policy: RedactionPolicy,
) -> TerraformResult:
    """Evaluate ``infra:plan``, run ``terraform plan``, dump JSON for apply."""
    receipt = await _evaluate_sidecar(
        chio_client=client,
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        subcommand="plan",
        parameters={
            "subcommand": "plan",
            "scope_label": scope_label,
            "working_dir": str(working_dir),
            "plan_path": str(plan_path),
            "args": extra_args,
        },
        redaction_policy=redaction_policy,
    )

    command = [
        terraform_binary,
        "plan",
        f"-out={plan_path}",
        *extra_args,
    ]
    completed = await asyncio.to_thread(
        _run_subprocess,
        command,
        cwd=working_dir,
        capture_output=capture_output,
        env=env,
    )

    if completed.returncode == 0:
        # Best-effort JSON dump; ``show`` failures aren't fatal for plan.
        show_command = [terraform_binary, "show", "-json", str(plan_path)]
        show = await asyncio.to_thread(
            _run_subprocess,
            show_command,
            cwd=working_dir,
            capture_output=True,
            env=env,
        )
        if show.returncode == 0 and show.stdout:
            try:
                json.loads(show.stdout)  # sanity check
            except json.JSONDecodeError:
                pass
            else:
                json_path = plan_path.with_suffix(plan_path.suffix + ".json")
                json_path.write_text(show.stdout, encoding="utf-8")

    return TerraformResult(
        subcommand="plan",
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        command=list(command),
        receipt=receipt,
        plan_path=str(plan_path),
    )


async def _run_apply_or_destroy(
    *,
    client: ChioClientLike,
    subcommand: str,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    scope_label: str,
    guard: PlanReviewGuard | None,
    working_dir: Path,
    plan_path: Path,
    extra_args: list[str],
    terraform_binary: str,
    env: dict[str, str] | None,
    capture_output: bool,
    redaction_policy: RedactionPolicy,
) -> TerraformResult:
    """PlanReviewGuard first (fast local deny), then sidecar, then apply."""
    plan_json_path = plan_path.with_suffix(plan_path.suffix + ".json")
    plan_payload = await _load_plan_payload(
        plan_path=plan_path,
        plan_json_path=plan_json_path,
        terraform_binary=terraform_binary,
        working_dir=working_dir,
        env=env,
    )

    resource_types: list[str] = []
    if guard is not None and plan_payload is not None:
        verdict = guard.review(plan_payload)
        resource_types = sorted({r.resource_type for r in verdict.resources if r.is_mutating})
        verdict.raise_for_violations(
            subcommand=subcommand,
            capability_id=capability_id,
        )
    elif guard is not None and plan_payload is None:
        raise ChioIACConfigError(
            f"terraform {subcommand} requires a plan JSON file at "
            f"{plan_json_path!s}; run `chio-iac terraform plan` first"
        )

    receipt = await _evaluate_sidecar(
        chio_client=client,
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        subcommand=subcommand,
        parameters={
            "subcommand": subcommand,
            "scope_label": scope_label,
            "working_dir": str(working_dir),
            "plan_path": str(plan_path),
            "resource_types": resource_types,
            "args": extra_args,
        },
        redaction_policy=redaction_policy,
    )

    if subcommand == "apply":
        command = [terraform_binary, "apply", str(plan_path), *extra_args]
    else:
        # ``destroy`` does not accept a plan file.
        command = [terraform_binary, "destroy", *extra_args]

    completed = await asyncio.to_thread(
        _run_subprocess,
        command,
        cwd=working_dir,
        capture_output=capture_output,
        env=env,
    )

    return TerraformResult(
        subcommand=subcommand,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        command=list(command),
        receipt=receipt,
        plan_path=str(plan_path),
        resource_types=resource_types,
    )


async def _load_plan_payload(
    *,
    plan_path: Path,
    plan_json_path: Path,
    terraform_binary: str,
    working_dir: Path,
    env: dict[str, str] | None,
) -> dict[str, Any] | None:
    """Load plan JSON: ``<plan>.json`` > ``plan_path`` (when ``.json``) > ``terraform show``."""
    if plan_json_path.exists():
        return json.loads(plan_json_path.read_text(encoding="utf-8"))

    if plan_path.suffix == ".json" and plan_path.exists():
        return json.loads(plan_path.read_text(encoding="utf-8"))

    if not plan_path.exists():
        return None

    show_command = [terraform_binary, "show", "-json", str(plan_path)]
    completed = await asyncio.to_thread(
        _run_subprocess,
        show_command,
        cwd=working_dir,
        capture_output=True,
        env=env,
    )
    if completed.returncode != 0:
        raise ChioIACConfigError(
            f"terraform show -json {plan_path!s} failed with exit "
            f"{completed.returncode}: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return json.loads(completed.stdout)


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
    "TerraformResult",
    "run_terraform",
]
