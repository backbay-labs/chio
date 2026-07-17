"""In-process test double for :class:`chio_sdk.client.ChioClient`.

This module ships a ``MockChioClient`` plus a few factory helpers
(``allow_all``, ``deny_all``, ``with_policy``) so Python developers can write
unit tests against the Chio SDK without needing a running sidecar kernel.

The mock matches the public async interface of :class:`ChioClient`. Each call
is recorded in ``client.calls`` so tests can assert what was evaluated. The
verdict a call produces is determined by a ``policy`` callable that receives
the tool name, scope-style dict, and arbitrary context; by default every
call is allowed.

Example
-------

.. code-block:: python

    from chio_sdk.testing import allow_all, deny_all, with_policy
    from chio_sdk.errors import ChioDeniedError

    async def test_mytool() -> None:
        async with allow_all() as chio:
            receipt = await chio.evaluate_tool_call(
                capability_id="cap-1",
                tool_server="srv",
                tool_name="read",
                parameters={"path": "/tmp"},
            )
            assert receipt.is_allowed
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from chio_sdk.errors import ChioDeniedError, ChioValidationError
from chio_sdk.models import (
    CallerIdentity,
    CapabilityToken,
    ChioReceipt,
    ChioScope,
    Decision,
    EvaluateResponse,
    GuardEvidence,
    HttpReceipt,
    ToolCallAction,
    Verdict,
    VerifyReceiptResponse,
)

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MockVerdict:
    """The outcome a policy produces for a mock Chio call.

    Parameters
    ----------
    allow:
        ``True`` to allow, ``False`` to deny.
    reason:
        Human-readable reason. Surfaced on deny verdicts via
        :class:`ChioDeniedError` and as ``Decision.reason``.
    guard:
        Name of the guard that produced the verdict. Defaults to
        ``"mock"``.
    evidence:
        Optional guard evidence to attach to the receipt. Useful for tests
        that assert on receipt contents.
    """

    allow: bool
    reason: str | None = None
    guard: str = "mock"
    evidence: tuple[GuardEvidence, ...] = ()

    @classmethod
    def allow_verdict(cls, *, guard: str = "mock", reason: str | None = None) -> MockVerdict:
        return cls(allow=True, guard=guard, reason=reason)

    @classmethod
    def deny_verdict(cls, reason: str, *, guard: str = "mock") -> MockVerdict:
        return cls(allow=False, reason=reason, guard=guard)


# ---------------------------------------------------------------------------
# Policy types
# ---------------------------------------------------------------------------


Policy = Callable[[str, dict[str, Any], dict[str, Any]], "MockVerdict | bool"]
"""Callable policy: ``(tool_name, scope, context) -> MockVerdict | bool``.

Returning ``True``/``False`` is shorthand for
:meth:`MockVerdict.allow_verdict` / :meth:`MockVerdict.deny_verdict` with a
generic reason.
"""


# ---------------------------------------------------------------------------
# Recorded call
# ---------------------------------------------------------------------------


@dataclass
class RecordedCall:
    """A single recorded interaction with the mock client."""

    method: str
    tool_name: str | None = None
    tool_server: str | None = None
    capability_id: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    verdict: MockVerdict | None = None


# ---------------------------------------------------------------------------
# Canonical helpers
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_synthetic_unsigned_receipt(receipt: ChioReceipt | HttpReceipt) -> bool:
    metadata = getattr(receipt, "metadata", None)
    return isinstance(metadata, Mapping) and metadata.get("chio_streaming_synthetic") is True


MOCK_PUBLIC_KEY = _sha256_hex(b"chio-sdk-python mock public key")
MOCK_POLICY_HASH = _sha256_hex(b"chio-sdk-python mock policy")
MOCK_CONTENT_HASH = _sha256_hex(b"chio-sdk-python mock content")
MOCK_SIGNATURE = "c" * 128


def _hex_or_hash(value: str) -> str:
    if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
        return value
    if value.startswith(("p256:", "p384:", "hybrid:")):
        return value
    return _sha256_hex(value.encode("utf-8"))


def _normalize_verdict(result: MockVerdict | bool | None) -> MockVerdict:
    """Coerce a policy return value into a :class:`MockVerdict`."""
    if result is None:
        return MockVerdict.allow_verdict()
    if isinstance(result, bool):
        if result:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict("policy denied")
    if isinstance(result, MockVerdict):
        return result
    raise ChioValidationError("policy must return MockVerdict, bool, or None")


# ---------------------------------------------------------------------------
# MockChioClient
# ---------------------------------------------------------------------------


class MockChioClient:
    """In-memory test double for :class:`chio_sdk.client.ChioClient`.

    Parameters
    ----------
    policy:
        Callable ``(tool_name, scope, context) -> MockVerdict | bool``
        that decides each call's verdict. Defaults to allow-all.
    raise_on_deny:
        When ``True`` (the default), denied tool calls raise
        :class:`ChioDeniedError` the same way the real HTTP client does on
        an HTTP 403. When ``False``, the mock returns a signed-looking
        receipt whose :class:`Decision` is a deny.

    Attributes
    ----------
    calls:
        List of :class:`RecordedCall` entries, one per public method
        invocation. Inspect this from tests to assert which tools were
        checked.
    """

    DEFAULT_BASE_URL = "http://mock.chio.local"

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        raise_on_deny: bool = True,
        kernel_key: str = MOCK_PUBLIC_KEY,
        policy_hash: str = MOCK_POLICY_HASH,
    ) -> None:
        self._policy: Policy = policy or (lambda _tool, _scope, _ctx: MockVerdict.allow_verdict())
        self._raise_on_deny = raise_on_deny
        self._kernel_key = _hex_or_hash(kernel_key)
        self._policy_hash = _hex_or_hash(policy_hash)
        self._closed = False
        self.calls: list[RecordedCall] = []

    # ------------------------------------------------------------------
    # Lifecycle (mirrors ChioClient)
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """No-op close; recorded so tests can assert lifecycle handling."""
        self._closed = True

    async def __aenter__(self) -> MockChioClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def set_policy(self, policy: Policy) -> None:
        """Swap in a new policy at runtime."""
        self._policy = policy

    def reset(self) -> None:
        """Clear the recorded call history."""
        self.calls.clear()

    def calls_for(self, tool_name: str) -> list[RecordedCall]:
        """Return recorded calls whose ``tool_name`` matches."""
        return [c for c in self.calls if c.tool_name == tool_name]

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Return a canned health payload."""
        self.calls.append(RecordedCall(method="health"))
        return {"status": "healthy", "mock": True}

    # ------------------------------------------------------------------
    # Capability tokens
    # ------------------------------------------------------------------

    async def create_capability(
        self,
        *,
        subject: str,
        scope: ChioScope,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Return a plausible, locally-generated capability token."""
        now = int(time.time())
        token = CapabilityToken(
            id=f"mock-tok-{uuid.uuid4().hex[:8]}",
            issuer=self._kernel_key,
            subject=_hex_or_hash(subject),
            scope=scope,
            issued_at=now,
            expires_at=now + ttl_seconds,
            signature=MOCK_SIGNATURE,
        )
        self.calls.append(
            RecordedCall(
                method="create_capability",
                scope=scope.model_dump(exclude_none=True),
                context={"subject": subject, "ttl_seconds": ttl_seconds},
            )
        )
        return token

    async def validate_capability(
        self,
        token: CapabilityToken,
    ) -> bool:
        """Return True if the token is not expired at ``now``."""
        now = int(time.time())
        is_valid = token.is_valid_at(now)
        self.calls.append(
            RecordedCall(
                method="validate_capability",
                capability_id=token.id,
                context={"valid": is_valid},
            )
        )
        return is_valid

    async def attenuate_capability(
        self,
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        """Fail closed like the real sidecar attenuation route."""
        if not new_scope.is_subset_of(token.scope):
            raise ChioValidationError("new_scope must be a subset of the parent token scope")
        self.calls.append(
            RecordedCall(
                method="attenuate_capability",
                capability_id=token.id,
                scope=new_scope.model_dump(exclude_none=True),
                context={"parent_id": token.id},
            )
        )
        raise ChioDeniedError(
            "capability attenuation requires the parent subject signer",
            reason="mock sidecar does not hold or derive subject signing keys",
            reason_code="chio_attenuation_requires_subject_signer",
        )

    # ------------------------------------------------------------------
    # Receipt verification
    # ------------------------------------------------------------------

    async def verify_receipt(self, receipt: ChioReceipt) -> bool:
        """Return ``True`` for any receipt whose ``kernel_key`` matches."""
        valid = (
            False
            if _is_synthetic_unsigned_receipt(receipt)
            else receipt.kernel_key == self._kernel_key or bool(receipt.signature)
        )
        self.calls.append(
            RecordedCall(
                method="verify_receipt",
                context={"receipt_id": receipt.id, "valid": valid},
            )
        )
        return valid

    async def verify_http_receipt(self, receipt: HttpReceipt) -> VerifyReceiptResponse:
        valid = (
            False
            if _is_synthetic_unsigned_receipt(receipt)
            else receipt.kernel_key == self._kernel_key or bool(receipt.signature)
        )
        self.calls.append(
            RecordedCall(
                method="verify_http_receipt",
                context={"receipt_id": receipt.id, "valid": valid},
            )
        )
        return VerifyReceiptResponse(
            signature_valid=valid,
            signer_trusted=valid,
            receipt_id_valid=bool(receipt.id),
            parameter_hash_valid=bool(receipt.content_hash),
            receipt_kind=receipt.receipt_kind,
            boundary_class=receipt.boundary_class,
            trust_level=receipt.trust_level,
            result="allow" if receipt.verdict.is_allowed else "deny",
            authorized=valid and receipt.is_allowed,
            signer_key_hex=receipt.kernel_key,
            ok=valid,
        )

    async def verify_receipt_chain(self, receipts: list[ChioReceipt]) -> bool:
        """Mirror the real client's content-hash chain check."""
        if len(receipts) < 2:
            return True
        for i in range(1, len(receipts)):
            prev_canonical = _canonical_json(receipts[i - 1].model_dump(exclude_none=True))
            expected_hash = _sha256_hex(prev_canonical)
            if receipts[i].content_hash != expected_hash:
                return False
        return True

    # ------------------------------------------------------------------
    # Tool evaluation (primary hook for policy)
    # ------------------------------------------------------------------

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        """Ask the configured policy whether the tool call is allowed.

        On allow, returns a synthetic :class:`ChioReceipt`. On deny, either
        raises :class:`ChioDeniedError` (default) or returns a deny receipt,
        depending on ``raise_on_deny``.
        """
        scope = {
            "tool_server": tool_server,
            "tool_name": tool_name,
        }
        context = {
            "capability_id": capability_id,
            "parameters": parameters,
        }
        verdict = _normalize_verdict(self._policy(tool_name, scope, context))
        recorded = RecordedCall(
            method="evaluate_tool_call",
            tool_name=tool_name,
            tool_server=tool_server,
            capability_id=capability_id,
            parameters=dict(parameters),
            scope=dict(scope),
            context={"capability_id": capability_id},
            verdict=verdict,
        )
        self.calls.append(recorded)

        if not verdict.allow and self._raise_on_deny:
            raise ChioDeniedError(
                verdict.reason or "denied by mock policy",
                guard=verdict.guard,
                reason=verdict.reason,
            )

        return self._build_tool_receipt(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
            verdict=verdict,
        )

    async def evaluate_http_request(
        self,
        *,
        request_id: str,
        method: str,
        route_pattern: str,
        path: str,
        caller: CallerIdentity,
        query: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body_hash: str | None = None,
        body_length: int = 0,
        session_id: str | None = None,
        capability_id: str | None = None,
        capability_token: str | None = None,
        timestamp: int | None = None,
    ) -> EvaluateResponse:
        """Run policy against an HTTP-style request and return a response.

        The policy's ``tool_name`` argument is set to ``route_pattern`` and
        the scope carries HTTP metadata. Deny verdicts raise
        :class:`ChioDeniedError` when ``raise_on_deny`` is true.
        """
        scope_for_policy: dict[str, Any] = {
            "method": method,
            "route_pattern": route_pattern,
            "path": path,
        }
        context: dict[str, Any] = {
            "request_id": request_id,
            "query": dict(query or {}),
            "headers": dict(headers or {}),
            "caller": caller.model_dump(exclude_none=True),
            "session_id": session_id,
            "capability_id": capability_id,
            "capability_token": capability_token,
        }
        mock_verdict = _normalize_verdict(self._policy(route_pattern, scope_for_policy, context))
        recorded = RecordedCall(
            method="evaluate_http_request",
            tool_name=route_pattern,
            capability_id=capability_id,
            scope=dict(scope_for_policy),
            context=context,
            verdict=mock_verdict,
        )
        self.calls.append(recorded)

        if not mock_verdict.allow and self._raise_on_deny:
            raise ChioDeniedError(
                mock_verdict.reason or "denied by mock policy",
                guard=mock_verdict.guard,
                reason=mock_verdict.reason,
            )

        ts = timestamp or int(time.time())
        verdict_model = (
            Verdict.allow()
            if mock_verdict.allow
            else Verdict.deny(
                reason=mock_verdict.reason or "denied by mock policy",
                guard=mock_verdict.guard,
            )
        )
        receipt = HttpReceipt(
            id=_sha256_hex(f"mock-hr-{uuid.uuid4().hex}".encode()),
            request_id=request_id,
            route_pattern=route_pattern,
            method=method,
            caller_identity_hash=_sha256_hex(_canonical_json(caller.model_dump(exclude_none=True))),
            session_id=session_id,
            verdict=verdict_model,
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            tool_origin="caller_executed",
            redaction_mode="none",
            evidence=list(mock_verdict.evidence),
            response_status=200 if mock_verdict.allow else 403,
            timestamp=ts,
            content_hash=MOCK_CONTENT_HASH,
            policy_hash=self._policy_hash,
            trust_level="mediated",
            capability_id=capability_id,
            kernel_key=self._kernel_key,
            signature=MOCK_SIGNATURE,
        )
        return EvaluateResponse(
            verdict=verdict_model,
            receipt=receipt,
            evidence=list(mock_verdict.evidence),
        )

    # ------------------------------------------------------------------
    # HITL approvals (mirrors ChioClient v0.2 surface)
    # ------------------------------------------------------------------

    async def list_pending_approvals(self) -> list[Any]:
        """Return the list of pending approvals submitted in-process."""
        from chio_sdk.models_approvals import PendingApproval

        approvals = getattr(self, "_pending_approvals", {})
        out: list[Any] = []
        for entry in approvals.values():
            out.append(PendingApproval.model_validate(entry))
        self.calls.append(RecordedCall(method="list_pending_approvals"))
        return out

    async def get_approval(self, approval_id: str) -> Any:
        from chio_sdk.errors import ChioError
        from chio_sdk.models_approvals import Approval, PendingApproval

        approvals = getattr(self, "_pending_approvals", {})
        resolved = getattr(self, "_resolved_approvals", {})
        self.calls.append(RecordedCall(method="get_approval", context={"approval_id": approval_id}))
        pending = approvals.get(approval_id)
        resolution = resolved.get(approval_id)
        if pending is None and resolution is None:
            raise ChioError(f"approval {approval_id} not found", code="HTTP_404")
        return Approval(
            pending=PendingApproval.model_validate(pending) if pending else None,
            resolution=resolution,
        )

    async def respond_approval(
        self,
        approval_id: str,
        verdict: Any,
        reason: str | None = None,
    ) -> Any:
        from chio_sdk.errors import ChioError
        from chio_sdk.models_approvals import (
            ApprovalResponse,
            ApprovalVerdict,
            ResolvedApproval,
        )

        normalised = ApprovalVerdict.from_action(verdict) if isinstance(verdict, str) else verdict
        approvals = getattr(self, "_pending_approvals", {})
        if approval_id not in approvals:
            raise ChioError(f"approval {approval_id} not found", code="HTTP_404")
        resolved = getattr(self, "_resolved_approvals", {})
        if not hasattr(self, "_resolved_approvals"):
            self._resolved_approvals = resolved
        del approvals[approval_id]
        now = int(time.time())
        resolved[approval_id] = ResolvedApproval(
            approval_id=approval_id,
            outcome=normalised,
            resolved_at=now,
            approver_hex="mock-approver",
            token_id=f"mock-tok-{approval_id}",
        )
        self.calls.append(
            RecordedCall(
                method="respond_approval",
                context={
                    "approval_id": approval_id,
                    "verdict": normalised.value,
                    "reason": reason,
                },
            )
        )
        return ApprovalResponse(
            approval_id=approval_id,
            outcome=normalised,
            resolved_at=now,
        )

    async def submit_for_approval(
        self,
        *,
        capability_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_server: str | None = None,
        requested_by: str | None = None,
        ttl_seconds: int = 3600,
        summary: str | None = None,
        triggered_by: list[str] | None = None,
    ) -> str:
        approvals: dict[str, Any] = getattr(self, "_pending_approvals", {})
        if not hasattr(self, "_pending_approvals"):
            self._pending_approvals = approvals
        approval_id = f"mock-ap-{uuid.uuid4().hex[:8]}"
        param_hash = _sha256_hex(_canonical_json(tool_args))
        now = int(time.time())
        approvals[approval_id] = {
            "approval_id": approval_id,
            "policy_id": "policy-mock",
            "subject_id": requested_by or "mock-subject",
            "capability_id": capability_id,
            "tool_server": tool_server or "shell",
            "tool_name": tool_name,
            "action": "invoke",
            "parameter_hash": param_hash,
            "expires_at": now + ttl_seconds,
            "created_at": now,
            "summary": summary or f"{tool_server}/{tool_name}",
            "triggered_by": list(triggered_by or []),
        }
        self.calls.append(
            RecordedCall(
                method="submit_for_approval",
                context={
                    "capability_id": capability_id,
                    "tool_name": tool_name,
                    "tool_server": tool_server,
                    "summary": summary,
                },
            )
        )
        return approval_id

    # ------------------------------------------------------------------
    # Guard evidence helpers (static, matches real client)
    # ------------------------------------------------------------------

    @staticmethod
    def collect_evidence(
        receipts: list[ChioReceipt],
    ) -> list[GuardEvidence]:
        evidence: list[GuardEvidence] = []
        for receipt in receipts:
            evidence.extend(receipt.evidence)
        return evidence

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_tool_receipt(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
        verdict: MockVerdict,
    ) -> ChioReceipt:
        param_canonical = _canonical_json(parameters)
        param_hash = _sha256_hex(param_canonical)
        decision = (
            Decision.allow()
            if verdict.allow
            else Decision.deny(
                reason=verdict.reason or "denied by mock policy",
                guard=verdict.guard,
            )
        )
        return ChioReceipt(
            id=_sha256_hex(f"mock-r-{uuid.uuid4().hex}".encode()),
            timestamp=int(time.time()),
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            action=ToolCallAction(
                parameters=dict(parameters),
                parameter_hash=param_hash,
            ),
            decision=decision,
            receipt_kind="mediated_decision",
            boundary_class="prevent",
            observation_outcome=None,
            tool_origin="caller_executed",
            redaction_mode="none",
            actor_chain=[],
            content_hash=MOCK_CONTENT_HASH,
            policy_hash=self._policy_hash,
            evidence=list(verdict.evidence),
            trust_level="mediated",
            kernel_key=self._kernel_key,
            signature=MOCK_SIGNATURE,
        )


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def allow_all(**kwargs: Any) -> MockChioClient:
    """Return a mock that allows every call."""
    return MockChioClient(
        policy=lambda _t, _s, _c: MockVerdict.allow_verdict(),
        **kwargs,
    )


def deny_all(
    reason: str = "denied by deny_all()",
    *,
    guard: str = "deny_all",
    **kwargs: Any,
) -> MockChioClient:
    """Return a mock that denies every call with a useful reason.

    By default, denied calls raise :class:`ChioDeniedError`. Pass
    ``raise_on_deny=False`` to receive deny receipts instead.
    """
    return MockChioClient(
        policy=lambda _t, _s, _c: MockVerdict.deny_verdict(reason, guard=guard),
        **kwargs,
    )


def with_policy(
    policy: Policy | Mapping[str, Any],
    **kwargs: Any,
) -> MockChioClient:
    """Return a mock configured with ``policy``.

    Accepts either:

    * A callable ``(tool_name, scope, context) -> MockVerdict | bool``.
    * A dict-based spec, e.g.::

          with_policy({
              "default": "allow",            # or "deny"
              "allow": ["read", "list"],     # exact tool names to allow
              "deny": {"write": "read-only session"},  # tool -> reason
          })

      When both ``allow`` and ``deny`` match, ``deny`` wins.
    """
    if callable(policy):
        return MockChioClient(policy=policy, **kwargs)
    if isinstance(policy, Mapping):
        return MockChioClient(policy=_compile_dict_policy(policy), **kwargs)
    raise ChioValidationError("policy must be a callable or a mapping spec")


def _compile_dict_policy(spec: Mapping[str, Any]) -> Policy:
    """Compile a dict-based policy spec into a callable."""
    default = str(spec.get("default", "allow")).lower()
    if default not in ("allow", "deny"):
        raise ChioValidationError("policy 'default' must be 'allow' or 'deny'")

    raw_allow = spec.get("allow") or []
    if isinstance(raw_allow, str):
        allow_names: set[str] = {raw_allow}
    else:
        allow_names = set(raw_allow)

    raw_deny = spec.get("deny") or {}
    deny_reasons: dict[str, str] = {}
    if isinstance(raw_deny, Mapping):
        for name, reason in raw_deny.items():
            deny_reasons[str(name)] = str(reason)
    else:
        for name in raw_deny:
            deny_reasons[str(name)] = "denied by policy spec"

    def _policy(
        tool_name: str,
        _scope: dict[str, Any],
        _context: dict[str, Any],
    ) -> MockVerdict:
        if tool_name in deny_reasons:
            return MockVerdict.deny_verdict(deny_reasons[tool_name])
        if tool_name in allow_names:
            return MockVerdict.allow_verdict()
        if default == "allow":
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(f"tool '{tool_name}' not in allow list")

    return _policy


__all__ = [
    "MockChioClient",
    "MockVerdict",
    "Policy",
    "RecordedCall",
    "allow_all",
    "deny_all",
    "with_policy",
]
