"""`RuntimeHandle`: per-`register(ctx)` plugin state container.

Bundles the live `ChioClient`, `CodeAgent` facade, active
`CodeAgentPolicy`, `ReceiptBuffer`, and resolved configuration.
Threaded into every handler / hook / slash factory via closure capture
so the plugin keeps no module-level mutable state.

Construction is fail-soft: missing env or a missing chio-code-agent
install yields a "degraded" handle whose `is_configured()` returns
False; tools registered against it short-circuit to `chio_not_configured`
JSON instead of crashing Hermes startup.

Hermes populates the process env from `plugins.entries.chio.*` and
`~/.hermes/.env` before invoking `register`, so this module only needs
to read process env directly.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SIDECAR_URL = "http://127.0.0.1:9090"


@dataclass
class RuntimeHandle:
    """All long-lived plugin state, owned by one `register(ctx)` call.

    The handle is fail-closed by construction: there is no fail-open
    escape hatch in v0.1.x. A future release may add one with
    sidecar-mediated semantics; until then any configuration gap
    surfaces as `chio_not_configured` from the tool envelope.
    """

    chio_client: Any | None = None
    capability_id: str | None = None
    code_agent: Any | None = None
    receipts: Any | None = None
    policy: Any | None = None
    sidecar_url: str = DEFAULT_SIDECAR_URL
    cwd: Path = field(default_factory=Path.cwd)
    init_error: str | None = None

    def is_configured(self) -> bool:
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


@dataclass
class _PolicyLoad:
    """Outcome of `_load_policy`.

    `policy` is the compiled policy on success, `None` on failure.
    `error` carries a human-readable reason on failure so the caller
    can surface `chio_not_configured` instead of silently falling back.
    """

    policy: Any | None
    error: str | None = None


def _load_policy() -> _PolicyLoad:
    """Compile the configured policy.

    Returns the bundled `DEFAULT_POLICY` only when `CHIO_POLICY_FILE`
    is unset. If the env var IS set but the file is missing or the YAML
    fails to compile, return a degraded `_PolicyLoad` so the caller can
    fail closed (the user explicitly opted into a custom policy; falling
    back to DEFAULT_POLICY would silently widen the trust surface).
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
        return _PolicyLoad(policy=None, error=f"chio_code_agent unavailable: {exc}")

    policy_path = os.environ.get("CHIO_POLICY_FILE")
    if not policy_path:
        return _PolicyLoad(policy=DEFAULT_POLICY)
    try:
        text = Path(policy_path).read_text(encoding="utf-8")
        return _PolicyLoad(policy=compile_policy(text))
    except Exception as exc:  # noqa: BLE001
        # Explicit user opt-in via CHIO_POLICY_FILE: fail closed rather
        # than silently fall back to DEFAULT_POLICY.
        print(
            f"[chio-hermes] failed to load CHIO_POLICY_FILE={policy_path!r}: {exc}",
            file=sys.stderr,
        )
        return _PolicyLoad(
            policy=None,
            error=f"policy_load_failed: {policy_path}: {exc}",
        )


def build_runtime_handle() -> RuntimeHandle:
    """Construct a `RuntimeHandle` from process env.

    Never raises. Any failure produces a degraded handle whose
    `is_configured()` returns False and whose `init_error` describes
    the problem.
    """
    from chio_hermes.receipts import ReceiptBuffer

    sidecar_url = os.environ.get("CHIO_SIDECAR_URL", DEFAULT_SIDECAR_URL)
    capability_id = os.environ.get("CHIO_CAPABILITY_ID")
    workspace_raw = os.environ.get("CHIO_WORKSPACE_ROOT")
    workspace_root = Path(workspace_raw).resolve() if workspace_raw else Path.cwd().resolve()

    handle = RuntimeHandle(
        sidecar_url=sidecar_url,
        capability_id=capability_id,
        cwd=workspace_root,
        receipts=ReceiptBuffer(),
    )

    load = _load_policy()
    if load.policy is None:
        handle.init_error = (
            load.error or "chio_code_agent is not importable"
        )
        return handle
    handle.policy = load.policy

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
    # Wrap evaluate_tool_call so the most recent allow-receipt id is
    # available to the envelope wrapper if the executor later raises.
    # See `chio_hermes.handlers._wrap_envelope` for the consumer side.
    _install_receipt_id_capture(client)
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
            policy=load.policy,
            cwd=workspace_root,
        )
    except Exception as exc:  # noqa: BLE001
        handle.init_error = f"failed to construct CodeAgent: {exc}"
        return handle

    return handle


def _install_receipt_id_capture(client: Any) -> None:
    """Patch `client.evaluate_tool_call` to publish the receipt id.

    The wrapper sets `chio_hermes.handlers._LAST_RECEIPT_ID` on every
    successful evaluate so a later executor exception can surface the
    receipt id from the prior allow verdict in
    `chio_executor_error` envelopes.
    """
    original = getattr(client, "evaluate_tool_call", None)
    if original is None or getattr(original, "__chio_hermes_wrapped__", False):
        return

    from chio_hermes.handlers import _LAST_RECEIPT_ID

    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        receipt = await original(*args, **kwargs)
        receipt_id = getattr(receipt, "id", None)
        if isinstance(receipt_id, str):
            _LAST_RECEIPT_ID.set(receipt_id)
        return receipt

    wrapped.__chio_hermes_wrapped__ = True  # type: ignore[attr-defined]
    try:
        client.evaluate_tool_call = wrapped
    except Exception:  # noqa: BLE001 - read-only client implementations
        pass


__all__ = [
    "DEFAULT_SIDECAR_URL",
    "RuntimeHandle",
    "build_runtime_handle",
]
