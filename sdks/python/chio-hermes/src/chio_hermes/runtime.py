"""`RuntimeHandle` (the per-`register(ctx)` plugin state container).

`RuntimeHandle` bundles the live `ChioClient`, the `CodeAgent` facade,
the active `CodeAgentPolicy`, the `ReceiptBuffer`, and the resolved
configuration. It is constructed inside `register(ctx)` and threaded
into every handler / hook / slash factory via closure capture so the
plugin keeps no module-level mutable state.

Construction is fail-soft: missing env vars or a missing chio-code-agent
install yield a "degraded" handle whose `is_configured()` returns False.
Tools registered against a degraded handle short-circuit to a
`chio_not_configured` error JSON instead of crashing Hermes startup.

Configuration source precedence (later overrides earlier):

1. `plugins.entries.chio.*` (lowest, supplied via Hermes config.yaml).
2. `~/.hermes/.env` (loaded by Hermes into the process env before
   `register` is called).
3. In-process env vars (highest).

We only see (3) at runtime; the precedence is implicit because Hermes
populates the process env from layers (1) and (2) before invoking us.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SIDECAR_URL = "http://127.0.0.1:9090"
"""Sidecar URL used when `CHIO_SIDECAR_URL` is unset."""


@dataclass
class RuntimeHandle:
    """All long-lived plugin state, owned by one `register(ctx)` call.

    Attributes
    ----------
    chio_client:
        Live `ChioClient` (or `None` in degraded mode).
    capability_id:
        Capability token id from `CHIO_CAPABILITY_ID`; `None` until set.
    code_agent:
        `CodeAgent` facade wired to `chio_client` + `policy` + cwd.
    receipts:
        `ReceiptBuffer` shared between handlers, hooks, and `/chio`.
    fail_open:
        When True, the *configuration-missing* path returns success-shaped
        empty JSON instead of an error. NEVER disables policy enforcement
        or sidecar deny verdicts. Documented as an unsafe escape hatch.
    policy:
        Compiled `CodeAgentPolicy` enforced by the pre-flight checks.
    sidecar_url:
        Resolved sidecar URL (kept for `/chio status`).
    cwd:
        Resolved workspace root the executors confine I/O to.
    init_error:
        Populated when construction failed; surfaced by `/chio status`.
    """

    chio_client: Any | None = None
    capability_id: str | None = None
    code_agent: Any | None = None
    receipts: Any | None = None
    fail_open: bool = False
    policy: Any | None = None
    sidecar_url: str = DEFAULT_SIDECAR_URL
    cwd: Path = field(default_factory=Path.cwd)
    init_error: str | None = None

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True when the plugin has both env vars + a live client."""
        return (
            self.chio_client is not None
            and self.code_agent is not None
            and bool(self.capability_id)
            and self.init_error is None
        )

    def masked_capability_id(self) -> str:
        """Return the last 8 chars of the capability id, or `<unset>`."""
        if not self.capability_id:
            return "<unset>"
        cap = self.capability_id
        return cap[-8:] if len(cap) > 8 else cap


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_policy() -> Any | None:
    """Compile the configured policy (or fall back to DEFAULT_POLICY).

    Returns `None` only when `chio_code_agent` itself is unimportable;
    callers must treat that as a degraded mode trigger.
    """
    try:
        from chio_code_agent.policy import (
            DEFAULT_POLICY,
            compile_policy,
        )
    except Exception as exc:  # noqa: BLE001
        print(
            f"[chio-hermes] chio_code_agent unavailable: {exc}",
            file=sys.stderr,
        )
        return None

    policy_path = os.environ.get("CHIO_POLICY_FILE")
    if not policy_path:
        return DEFAULT_POLICY
    try:
        text = Path(policy_path).read_text(encoding="utf-8")
        return compile_policy(text)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[chio-hermes] failed to load CHIO_POLICY_FILE={policy_path!r}: {exc}",
            file=sys.stderr,
        )
        return DEFAULT_POLICY


def build_runtime_handle() -> RuntimeHandle:
    """Construct a `RuntimeHandle` from process env.

    Never raises. Any failure produces a degraded handle whose
    `is_configured()` returns False and whose `init_error` describes
    the problem. Tools dispatched against a degraded handle return the
    `chio_not_configured` JSON shape instead of crashing the worker.
    """
    from chio_hermes.receipts import ReceiptBuffer

    sidecar_url = os.environ.get("CHIO_SIDECAR_URL", DEFAULT_SIDECAR_URL)
    capability_id = os.environ.get("CHIO_CAPABILITY_ID")
    fail_open = _truthy(os.environ.get("CHIO_FAIL_OPEN"))
    workspace_raw = os.environ.get("CHIO_WORKSPACE_ROOT")
    workspace_root = Path(workspace_raw).resolve() if workspace_raw else Path.cwd().resolve()

    handle = RuntimeHandle(
        sidecar_url=sidecar_url,
        capability_id=capability_id,
        fail_open=fail_open,
        cwd=workspace_root,
        receipts=ReceiptBuffer(),
    )

    policy = _load_policy()
    if policy is None:
        handle.init_error = "chio_code_agent is not importable"
        return handle
    handle.policy = policy

    try:
        from chio_sdk.client import ChioClient
    except Exception as exc:  # noqa: BLE001
        handle.init_error = f"chio_sdk unavailable: {exc}"
        return handle

    try:
        client = ChioClient(base_url=sidecar_url)
    except Exception as exc:  # noqa: BLE001
        handle.init_error = f"failed to construct ChioClient: {exc}"
        return handle
    handle.chio_client = client

    if not capability_id:
        handle.init_error = (
            "CHIO_CAPABILITY_ID is unset; run `hermes chio issue` to mint one"
        )
        return handle

    try:
        from chio_code_agent.agent import CodeAgent

        handle.code_agent = CodeAgent(
            chio_client=client,
            capability_id=capability_id,
            policy=policy,
            cwd=workspace_root,
        )
    except Exception as exc:  # noqa: BLE001
        handle.init_error = f"failed to construct CodeAgent: {exc}"
        return handle

    return handle


__all__ = [
    "DEFAULT_SIDECAR_URL",
    "RuntimeHandle",
    "build_runtime_handle",
]
