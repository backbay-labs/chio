"""Terraform CLI wrapper with two-phase Chio capability enforcement.

Call flow
---------

::

    chio-iac terraform plan
            |
            v
    Chio evaluate  -- scope: infra:plan, tool: terraform:plan
            |
            | allow
            v
    terraform plan -out=tfplan
            |
            v
    terraform show -json tfplan  -> plan.json


    chio-iac terraform apply
            |
            v
    PlanReviewGuard parses plan.json,
    denies out-of-scope resource types
            |
            | allow
            v
    Chio evaluate  -- scope: infra:apply, tool: terraform:apply
            |
            | allow
            v
    terraform apply tfplan
            |
            v
    Chio receipt stored via sidecar

The plan / apply split maps directly to Chio's two-tier capability model:

* ``infra:plan`` is low-privilege -- it reads configuration, queries
  providers, and produces a plan file. It never mutates the cloud.
* ``infra:apply`` is high-privilege -- it actually runs the plan against
  the cloud. It must be accompanied by a plan-review guard that parses
  the plan output and ensures every resource the plan touches is within
  the granted scope.

The wrapper is deliberately thin: it shells out to ``terraform`` as a
subprocess and never links the Terraform Go binary. That keeps the
Python side small and lets us mock the subprocess layer in tests without
requiring a live Terraform install.
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

# Any object that quacks like an :class:`chio_sdk.client.ChioClient` --
# accepts the real client plus :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any


#: Terraform subcommands the wrapper recognises. Each maps to the scope
#: it enforces on the sidecar call. Subcommands not in this map are
#: rejected with :class:`ChioIACConfigError`.
_SUBCOMMAND_SCOPE: dict[str, str] = {
    "plan": "infra:plan",
    "apply": "infra:apply",
    "destroy": "infra:apply",
}

#: Default tool-name per subcommand. Kernel policies can key on this.
_TOOL_NAME_FOR: dict[str, str] = {
    "plan": "terraform:plan",
    "apply": "terraform:apply",
    "destroy": "terraform:destroy",
}

#: Subcommands that require the plan-review guard to run before dispatch.
_APPLY_SUBCOMMANDS: frozenset[str] = frozenset({"apply", "destroy"})


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TerraformResult:
    """Return value of :func:`run_terraform`.

    The result is returned only for the allow path; the deny path raises
    :class:`ChioIACError` (or :class:`ChioIACPlanReviewError`) before
    ``terraform`` is dispatched.

    Attributes
    ----------
    subcommand:
        The Terraform subcommand that was executed (``plan``,
        ``apply``, ``destroy``).
    returncode:
        Process exit code from ``terraform``. ``0`` on success.
    stdout / stderr:
        Captured streams. Empty strings when ``capture_output`` was
        False and the streams were forwarded to the parent TTY.
    command:
        Full argv actually dispatched -- useful for structured logs.
    receipt:
        :class:`ChioReceipt` the sidecar signed for the allow verdict.
        ``None`` on the rare path where the wrapper was called with a
        mock that returned a bare receipt id.
    plan_path:
        Absolute path of the saved plan file when the subcommand is
        ``plan``. ``None`` for ``apply`` / ``destroy``.
    resource_types:
        Sorted list of mutating resource types surfaced by the
        plan-review guard on ``apply`` / ``destroy``. ``[]`` for
        ``plan``.
    """

    subcommand: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    command: list[str] = field(default_factory=list)
    receipt: ChioReceipt | None = None
    plan_path: str | None = None
    resource_types: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Terraform binary discovery and subprocess plumbing
# ---------------------------------------------------------------------------


def _resolve_terraform_binary(override: str | None) -> str:
    """Return the path of the ``terraform`` binary to invoke.

    ``override`` wins when set. Otherwise we consult ``$CHIO_IAC_TERRAFORM``
    to let CI pin a version, and fall back to :func:`shutil.which`.
    Raises :class:`ChioIACConfigError` when no binary can be located.
    """
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
    """Subprocess wrapper the tests monkey-patch for deterministic runs.

    Kept as a module-level function (rather than an inline call) so
    tests can replace it with a recorder without touching
    :mod:`subprocess` globals.
    """
    return subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=capture_output,
        text=True,
        env=env,
        check=False,
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
    subcommand: str,
    parameters: dict[str, Any],
    redaction_policy: RedactionPolicy,
) -> ChioReceipt:
    """Call the sidecar ``/v1/evaluate`` endpoint and translate denies.

    Raises :class:`ChioIACError` on deny (both receipt-path and HTTP-403
    paths). Transport / kernel errors propagate as :class:`ChioError` so
    callers can retry without conflating them with policy denials.
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

    if receipt.is_denied:
        decision = receipt.decision
        raise ChioIACError(
            f"Chio denied terraform {subcommand}: "
            f"{decision.reason or 'denied by Chio kernel'}",
            subcommand=subcommand,
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
# Core entry point
# ---------------------------------------------------------------------------


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

    Two-phase enforcement:

    * ``plan`` -- evaluates the ``infra:plan`` scope on the sidecar,
      then runs ``terraform plan -out=tfplan``. Safe by design: the
      plan never mutates the cloud. On allow the wrapper also writes a
      JSON dump (via ``terraform show -json``) to ``plan_path + ".json"``
      so ``apply`` can review the plan without re-running
      ``terraform show``.

    * ``apply`` / ``destroy`` -- loads the plan JSON (from
      ``plan_path + ".json"`` or ``plan_path`` when it is already a
      ``*.json`` dump), runs the :class:`PlanReviewGuard` to check every
      mutating resource type against the allowlist / denylist, then
      evaluates the ``infra:apply`` scope on the sidecar. Only then is
      ``terraform apply`` dispatched.

    Parameters
    ----------
    subcommand:
        ``plan``, ``apply``, or ``destroy``. Anything else raises
        :class:`ChioIACConfigError`.
    args:
        Extra positional arguments to pass to ``terraform``. Appended
        *after* the wrapper-managed flags (e.g. ``-out=tfplan``), so
        they take precedence when duplicated.
    capability_id:
        Required. The pre-minted capability token id to evaluate.
    tool_server:
        Chio tool-server id used in the sidecar evaluation. Defaults to
        ``"terraform"``.
    working_dir:
        Directory containing the Terraform configuration. Defaults to
        the current process cwd.
    plan_path:
        Override for the Terraform plan file path. Defaults to
        ``<working_dir>/tfplan`` for ``plan`` and
        ``<working_dir>/tfplan`` for ``apply`` / ``destroy``. The JSON
        dump used by the plan-review guard sits at ``<plan_path>.json``.
    plan_review_guard:
        Optional pre-built :class:`PlanReviewGuard`. When unset, the
        wrapper constructs a guard from ``allowlist`` / ``denylist``
        / ``allow_destroy``.
    allowlist / denylist / allow_destroy:
        Shortcut for constructing a :class:`PlanReviewGuard` when the
        caller has not supplied one. Ignored when ``plan_review_guard``
        is set.
    chio_client / sidecar_url:
        The :class:`chio_sdk.client.ChioClient` (or mock) to use. When
        neither is provided, the wrapper mints a client pointing at
        ``http://127.0.0.1:9090``.
    terraform_binary:
        Override for the ``terraform`` binary path (useful in CI where
        a pinned version is needed). Falls back to ``$CHIO_IAC_TERRAFORM``
        and then ``$PATH``.
    env:
        Extra environment variables merged into ``os.environ`` for the
        ``terraform`` subprocess. Useful for provider credentials or
        ``TF_LOG=debug``.
    capture_output:
        When True (default), stdout / stderr are captured and returned.
        When False, the streams are forwarded to the parent terminal --
        useful for interactive plans.
    redaction_policy:
        Optional :class:`RedactionPolicy` applied to the parameters
        dict before it is forwarded to the sidecar. Defaults to
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
    """Build (or reuse) the plan-review guard for apply-family subcommands."""
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


# ---------------------------------------------------------------------------
# ``terraform plan``
# ---------------------------------------------------------------------------


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
    """Evaluate ``infra:plan`` scope, then run ``terraform plan``.

    On success the plan is written to ``plan_path`` (binary) and its
    JSON dump to ``plan_path.json`` so a subsequent ``apply`` can review
    the plan without re-shelling into ``terraform show``.
    """
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
        # Best-effort: dump the plan to JSON so apply can review it.
        # ``terraform show`` failures are not fatal for plan; they just
        # mean apply will have to re-run ``show`` itself.
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


# ---------------------------------------------------------------------------
# ``terraform apply`` / ``terraform destroy``
# ---------------------------------------------------------------------------


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
    """Run the plan-review guard, then evaluate ``infra:apply``, then apply.

    The plan-review guard denies out-of-scope resource types before any
    sidecar call so local operators get fast feedback on allowlist
    violations. The sidecar is then evaluated with the scope_label and
    the list of resource types the plan touches; the kernel can apply
    additional guards (monetary budgets, environment checks, etc.).
    """
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
        # ``terraform destroy`` does not accept a plan file; use
        # ``-auto-approve`` only when the caller opted in.
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
    """Load a plan JSON dict for the plan-review guard.

    Tries three sources in order:

    1. ``plan_json_path`` (the ``.json`` sidecar the plan phase writes).
    2. ``plan_path`` itself when it already ends in ``.json`` -- useful
       for callers who pre-render the plan via ``terraform show``.
    3. ``terraform show -json plan_path`` as a last resort.

    Returns ``None`` when the plan file does not exist; the caller
    decides whether that is a fatal error.
    """
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


# ---------------------------------------------------------------------------
# ChioClient ownership helper (mirrors chio-prefect)
# ---------------------------------------------------------------------------


class _ChioClientOwner:
    """Owns a lazily-constructed :class:`ChioClient` for one wrapper call.

    The wrapper may be called with an explicit client (from a test
    fixture or a caller-managed session) or may need to mint a default.
    We track ownership so we only close clients we created ourselves.
    """

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
